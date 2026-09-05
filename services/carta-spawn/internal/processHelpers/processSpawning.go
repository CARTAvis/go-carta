package processHelpers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"

	"github.com/gorilla/websocket"

	"github.com/CARTAvis/go-carta/pkg/config"
	helpers "github.com/CARTAvis/go-carta/pkg/shared"
)

// package-scope regex and parser for worker readiness log lines
var listenRe = regexp.MustCompile(`Listening on port (\d+) with top level folder`)

// validUsername bounds what a username may look like when it is not checked
// against the OS, since it is interpolated into the worker's start directory.
var validUsername = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]*$`)

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

// Worker is a running backend process. It is reaped by a single goroutine
// started at spawn time, so callers signal it and wait rather than calling
// Wait themselves.
type Worker struct {
	cmd    *exec.Cmd
	Port   int
	exited chan struct{}
}

// lineWriter forwards everything written to it while calling onLine for each
// complete line. It stands in for a pipe so exec.Cmd owns the plumbing and
// Wait can be called safely.
type lineWriter struct {
	out    io.Writer
	onLine func(string)

	mu      sync.Mutex
	partial []byte
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.out.Write(p); err != nil {
		slog.Debug("Failed to forward worker output", "error", err)
	}
	w.partial = append(w.partial, p...)
	for {
		i := bytes.IndexByte(w.partial, '\n')
		if i < 0 {
			break
		}
		w.onLine(string(bytes.TrimRight(w.partial[:i], "\r")))
		w.partial = w.partial[i+1:]
	}
	return len(p), nil
}

// lookupUser resolves the account the worker will run as. With
// RunAsCurrentUser the requested username need not be a real OS account.
func lookupUser(username string, runAsCurrentUser bool) (*user.User, error) {
	if runAsCurrentUser {
		if !validUsername.MatchString(username) {
			return nil, fmt.Errorf("invalid username %q", username)
		}
		usr, err := user.Current()
		if err != nil {
			return nil, fmt.Errorf("failed to look up the current user: %w", err)
		}
		return usr, nil
	}
	usr, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("failed to look up user %s: %w", username, err)
	}
	return usr, nil
}

func workerArgs(cfg config.SpawnerConfig, username string, usr *user.User) ([]string, error) {
	args := []string{"--debug_no_auth"}
	args = append(args, "--no_frontend")
	args = append(args, "--no_database")
	args = append(args, "--controller_deployment")
	args = append(args, "--verbosity", "5")
	args = append(args, "--exit_timeout", "10")
	args = append(args, "--initial_timeout", "20")
	args = append(args, "--idle_timeout", "300")
	if cfg.TopLevelDir != "" {
		args = append(args, "--top_level_folder", cfg.TopLevelDir)
	}

	// Adding as a positional argument so startup folder should be last option
	if strings.Contains(cfg.BaseDirTmpl, "{{.home}}") && usr.HomeDir == "" {
		slog.Warn("base_dir_tmpl references {{.home}} but user has no home directory. Omitting starting directory", "username", username)
		return args, nil
	}
	if cfg.BaseDirTmpl == "" {
		return args, nil
	}

	tmpl, err := template.New("base_dir_tmpl").Parse(cfg.BaseDirTmpl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base_dir_tmpl: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, map[string]string{"user": username, "home": usr.HomeDir}); err != nil {
		return nil, fmt.Errorf("failed to execute base_dir_tmpl: %w", err)
	}
	resolvedDir := buf.String()
	slog.Debug("Resolved base directory from template", "template", cfg.BaseDirTmpl, "resolved", resolvedDir)

	info, err := os.Stat(resolvedDir)
	if err != nil {
		slog.Error("Failed to stat resolved base directory. Omitting it.", "directory", resolvedDir, "error", err)
	} else if !info.IsDir() {
		slog.Warn("Resolved base directory is not a directory. Omitting it.", "directory", resolvedDir)
	} else {
		args = append(args, resolvedDir)
	}
	return args, nil
}

// SpawnWorker starts a new worker process and waits until it logs that it is
// listening, returning the port it reported.
func SpawnWorker(ctx context.Context, cfg config.SpawnerConfig, username string) (*Worker, error) {
	usr, err := lookupUser(username, cfg.RunAsCurrentUser)
	if err != nil {
		return nil, err
	}
	args, err := workerArgs(cfg, username, usr)
	if err != nil {
		return nil, err
	}

	slog.Info("Spawning worker process", "workerPath", cfg.WorkerExec, "username", username, "runAsCurrentUser", cfg.RunAsCurrentUser, "args", args)

	var cmd *exec.Cmd
	if cfg.RunAsCurrentUser {
		cmd = exec.CommandContext(ctx, cfg.WorkerExec, args...)
	} else {
		cmd = exec.CommandContext(ctx, "sudo", append([]string{"-u", username, cfg.WorkerExec}, args...)...)
	}

	// The worker runs in its own session, and so its own process group, so
	// signals reach the backend even when cmd.Process is a sudo wrapper.
	// Detaching from the controlling terminal also stops sudo allocating a
	// pty, which would move the backend into a session of its own.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	w := &Worker{cmd: cmd, exited: make(chan struct{})}
	// Cancelling ctx asks the worker's group to exit rather than killing only
	// the wrapper, which is what the default cancel would do.
	cmd.Cancel = func() error { return w.Signal(syscall.SIGTERM) }

	// Readiness is detected from the worker's own output, which exec.Cmd
	// copies for us so that reaping it later is safe.
	readyCh := make(chan int, 1)
	onLine := func(line string) {
		if p, ok := parsePortFromLine(line); ok {
			slog.Info("Detected worker port from log", "port", p)
			select {
			case readyCh <- p:
			default:
			}
		}
	}
	cmd.Stdout = &lineWriter{out: os.Stdout, onLine: onLine}
	cmd.Stderr = &lineWriter{out: os.Stderr, onLine: onLine}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start worker: %w", err)
	}
	go func() {
		_ = cmd.Wait()
		close(w.exited)
	}()

	ctxReady, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	select {
	case port := <-readyCh:
		w.Port = port
		return w, nil
	case <-w.exited:
		return nil, fmt.Errorf("worker exited before it was ready")
	case <-ctxReady.Done():
		_ = w.Kill()
		return nil, fmt.Errorf("worker did not become ready in time: %w", ctxReady.Err())
	}
}

// Alive reports whether the worker process is still running.
func (w *Worker) Alive() bool {
	select {
	case <-w.exited:
		return false
	default:
		return true
	}
}

// ExitedCleanly reports whether a worker that has exited did so with success.
func (w *Worker) ExitedCleanly() bool {
	select {
	case <-w.exited:
		return w.cmd.ProcessState != nil && w.cmd.ProcessState.Success()
	default:
		return false
	}
}

func (w *Worker) Pid() int {
	if w.cmd.Process == nil {
		return 0
	}
	return w.cmd.Process.Pid
}

// Signal sends sig to the worker's process group, whose id is the worker's pid
// since it was started with Setsid.
func (w *Worker) Signal(sig syscall.Signal) error {
	if w.cmd.Process == nil {
		return fmt.Errorf("worker has no process")
	}
	if !w.Alive() {
		return os.ErrProcessDone
	}
	return syscall.Kill(-w.cmd.Process.Pid, sig)
}

// gone reports whether err means the worker was already finished.
func gone(err error) bool {
	return err == nil || errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.ESRCH)
}

// Kill force-kills the worker's process group and waits for it to be reaped.
func (w *Worker) Kill() error {
	if err := w.Signal(syscall.SIGKILL); !gone(err) {
		return err
	}
	<-w.exited
	return nil
}

// Stop asks the worker's process group to exit, force-killing it if it is
// still running after grace.
func (w *Worker) Stop(grace time.Duration) error {
	if err := w.Signal(syscall.SIGTERM); !gone(err) {
		return err
	}
	select {
	case <-w.exited:
		return nil
	case <-time.After(grace):
		slog.Warn("Worker did not exit in time, force killing", "pid", w.Pid())
		return w.Kill()
	}
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
