package processHelpers

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"text/template"
	"time"

	"github.com/gorilla/websocket"

	helpers "github.com/CARTAvis/go-carta/pkg/shared"
)

// package-scope regex and parser for worker readiness log lines
var listenRe = regexp.MustCompile(`Listening on port (\d+) with top level folder`)

func parsePortFromLine(line string) (int, bool) {
	m := listenRe.FindStringSubmatch(line)
	if len(m) != 2 {
		return 0, false
	}
	p, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return p, true
}

// SpawnWorker starts a new worker process and waits until the worker logs that
// it is listening ("server listening at ..."). The worker is started with
// -port=0 so the OS selects a free port, and the detected port from the log is
// returned.
func SpawnWorker(ctx context.Context, workerPath string, timeoutDuration time.Duration, username string, baseDirTmpl string, topLevelDir string, runAsCurrentUser bool) (*exec.Cmd, int, error) {
	// runAsCurrentUser launches the worker directly as the process owner (no
	// sudo); otherwise it sudo's to the requested OS account. In the current-user
	// case the requested username need not be a real OS account, so resolve the
	// home directory (for base_dir_tmpl) from the running user instead.
	var usr *user.User
	var err error
	if runAsCurrentUser {
		usr, err = user.Current()
	} else {
		usr, err = user.Lookup(username)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("failed to look up user %s: %w", username, err)
	}

	args := []string{"--debug_no_auth"}
	args = append(args, "--no_frontend")
	args = append(args, "--no_database")
	args = append(args, "--controller_deployment")
	args = append(args, "--verbosity", "5")
	args = append(args, "--exit_timeout", "10")
	args = append(args, "--initial_timeout", "20")
	args = append(args, "--idle_timeout", "300")
	if topLevelDir != "" {
		args = append(args, "--top_level_folder", topLevelDir)
	}

	// Adding as a positional argument so startup folder should be last option
	if strings.Contains(baseDirTmpl, "{{.home}}") && usr.HomeDir == "" {
		slog.Warn("base_dir_tmpl references {{.home}} but user has no home directory. Omitting starting directory", "username", username)
	} else if baseDirTmpl != "" {
		var buf bytes.Buffer
		tmpl, err := template.New("base_dir_tmpl").Parse(baseDirTmpl)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to parse base_dir_tmpl: %w", err)
		}

		err = tmpl.Execute(&buf, map[string]string{
			"user": username,
			"home": usr.HomeDir,
		})
		if err != nil {
			return nil, 0, fmt.Errorf("failed to execute base_dir_tmpl: %w", err)
		}
		resolvedDir := buf.String()
		slog.Debug("Resolved base directory from template", "template", baseDirTmpl, "resolved", resolvedDir)
		info, err := os.Stat(resolvedDir)
		if err != nil {
			slog.Error("Failed to stat resolved base directory. Omitting it.", "directory", resolvedDir, "error", err)
		} else if !info.IsDir() {
			slog.Warn("Resolved base directory is not a directory. Omitting it.", "directory", resolvedDir)
		} else {
			args = append(args, resolvedDir)
		}
	}

	slog.Info("Spawning worker process", "workerPath", workerPath, "username", username, "runAsCurrentUser", runAsCurrentUser, "args", args)

	var cmd *exec.Cmd
	if runAsCurrentUser {
		cmd = exec.CommandContext(ctx, workerPath, args...)
	} else {
		cmd = exec.CommandContext(ctx, "sudo", append([]string{"-u", username, workerPath}, args...)...)
	}

	// Put the worker in its own process group. In the sudo case cmd.Process is
	// the sudo wrapper, not the backend; killing only that PID would orphan the
	// backend. With a dedicated group, KillWorker can signal the whole group so
	// the backend is actually reaped.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Capture stdout/stderr so we can watch for the readiness log while still
	// forwarding output to the parent process' stdio.
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get stdout pipe: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get stderr pipe: %w", err)
	}

	// Start the worker process.
	if err := cmd.Start(); err != nil {
		return nil, 0, fmt.Errorf("failed to start worker: %w", err)
	}

	// Channel to signal readiness once the expected log line is observed
	// (carries the detected port).
	readyCh := make(chan int, 1)

	slog.Debug("Worker process started, waiting for readiness")

	// TODO: I need to go over this code a bit more
	// Helper to scan a pipe, forward lines, and watch for readiness.
	watch := func(r io.Reader, w io.Writer) {
		s := bufio.NewScanner(r)
		for s.Scan() {
			line := s.Text()
			// Forward the line to the appropriate writer.
			_, err := fmt.Fprintln(w, line)
			if err != nil {
				return
			}
			// Detect readiness: parse port from log line.
			slog.Debug("Scanning line for port info", "line", line)
			if p, ok := parsePortFromLine(line); ok {
				slog.Info("Detected worker port from log", "port", p)
				// Send detected port if not already sent.
				select {
				case readyCh <- p:
				default:
				}
			}
			slog.Debug("Finished scanning line", "line", line)
		}
	}

	slog.Debug("Starting to watch worker stdout/stderr for readiness")

	// Start scanning goroutines.
	go watch(stdoutPipe, os.Stdout)
	go watch(stderrPipe, os.Stderr)

	slog.Debug("Watching worker output for readiness")

	// Wait for readiness or timeout; kill the worker on failure.
	ctxReady, cancel := context.WithTimeout(ctx, timeoutDuration)
	defer cancel()
	select {
	case p := <-readyCh:
		return cmd, p, nil
	case <-ctxReady.Done():
		_ = KillWorker(cmd)
		_ = cmd.Wait()
		return nil, 0, fmt.Errorf("worker did not become ready in time: %w", ctxReady.Err())
	}
}

// SignalWorker sends sig to the worker's whole process group. Workers are
// spawned with Setpgid, so the group id equals the spawned process' PID; in the
// sudo case this reaches the backend, not just the sudo wrapper (which would
// otherwise be orphaned). Returns an error if the worker has no live process.
func SignalWorker(cmd *exec.Cmd, sig syscall.Signal) error {
	if cmd == nil || cmd.Process == nil {
		return fmt.Errorf("worker has no process")
	}
	return syscall.Kill(-cmd.Process.Pid, sig)
}

// KillWorker force-kills the worker's process group (SIGKILL).
func KillWorker(cmd *exec.Cmd) error {
	return SignalWorker(cmd, syscall.SIGKILL)
}

func TestWorker(ctx context.Context, port int, timeoutDuration time.Duration) error {
	addr := fmt.Sprintf("ws://localhost:%d", port)

	rpcCtx, cancel := context.WithTimeout(ctx, timeoutDuration)
	defer cancel()
	// Connect to the worker websocket
	conn, _, err := websocket.DefaultDialer.DialContext(rpcCtx, addr, nil)
	if err != nil {
		return err
	}
	defer helpers.CloseOrLog(conn)

	// Send a PING text message and wait for a PONG
	err = conn.WriteMessage(websocket.TextMessage, []byte("PING"))
	if err != nil {
		return err
	}
	messageType, message, err := conn.ReadMessage()
	if err != nil {
		return err
	}
	if messageType != websocket.TextMessage {
		return fmt.Errorf("expected text message, got %d", messageType)
	}
	if string(message) != "PONG" {
		return fmt.Errorf("expected PONG, got %s", string(message))
	}

	return nil
}
