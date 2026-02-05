package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/pflag"

	"github.com/CARTAvis/go-carta/pkg/config"
	helpers "github.com/CARTAvis/go-carta/pkg/shared"
	"github.com/CARTAvis/go-carta/services/carta-spawn/internal/httpHelpers"
	"github.com/CARTAvis/go-carta/services/carta-spawn/internal/processHelpers"
)

type WorkerInfo struct {
	Process *exec.Cmd
	Port    int
}

func main() {
	logger := helpers.NewLogger("carta-spawn", "info")
	slog.SetDefault(logger)

	id := uuid.New()
	slog.Info("Starting spawner", "uuid", id.String())

	pflag.String("config", "", "Path to config file (default: /etc/carta/config.toml)")
	pflag.String("log_level", "info", "Log level (debug|info|warn|error)")
	pflag.Int("port", 8080, "HTTP server port")
	pflag.String("hostname", "", "Hostname to listen on")
	pflag.String("worker_exec", "carta_backend", "Path to worker executable")
	pflag.Int("timeout", 5, "Spawn timeout in seconds")
	pflag.String("override", "", "Override simple config values (string, int, bool) as comma-separated key:value pairs (e.g., spawner.port:9000,log_level:debug)")

	pflag.Parse()

	config.BindFlags(map[string]string{
		"log_level":   "log_level",
		"port":        "spawner.port",
		"hostname":    "spawner.hostname",
		"worker_exec": "spawner.worker_exec",
		"timeout":     "spawner.timeout",
	})

	cfg := config.Load(pflag.Lookup("config").Value.String(), pflag.Lookup("override").Value.String())

	// Update the logger to use the configured log level
	logger = helpers.NewLogger("carta-spawn", cfg.LogLevel)
	slog.SetDefault(logger)

	// Global context that cancels all spawned processes on SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	workerMap := make(map[string]*WorkerInfo)

	r := http.NewServeMux()

	// Start a new worker
	r.Handle("POST /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()

		// parse the optional base folder from the request body
		var reqBody struct {
			BaseFolder string `json:"baseFolder"`
		}
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			slog.Error("Error decoding request body", "error", err)
			httpHelpers.WriteError(w, http.StatusBadRequest, "Error decoding request body")
			return
		}

		slog.Info("Process started", "baseFolder", reqBody.BaseFolder)

		cmd, port, err := processHelpers.SpawnWorker(ctx, cfg.Spawner.WorkerExec, cfg.Spawner.Timeout, reqBody.BaseFolder)
		spawnerDuration := time.Since(startTime)
		if err != nil {
			slog.Error("Error spawning worker on free port", "error", err)
			httpHelpers.WriteError(w, http.StatusInternalServerError, "Error spawning worker")
			return
		}
		slog.Info("Started worker", "port", port)

		startTime = time.Now()
		err = processHelpers.TestWorker(ctx, port, 2*time.Second)
		testWorkerDuration := time.Since(startTime)
		if err != nil {
			slog.Error("Error connecting to worker", "error", err)
			err := cmd.Process.Kill()
			if err != nil {
				slog.Error("Error killing worker", "error", err)
			}
			httpHelpers.WriteError(w, http.StatusInternalServerError, "Error connecting to worker")
			return
		}
		slog.Info("Connected to worker", "port", port)
		workerId := uuid.New()
		workerMap[workerId.String()] = &WorkerInfo{
			Process: cmd,
			Port:    port,
		}
		httpHelpers.WriteTimings(w, httpHelpers.Timings{"spawn-time": spawnerDuration, "check-time": testWorkerDuration})

		workerHostname := cfg.Spawner.Hostname
		if workerHostname == "" {
			workerHostname = "localhost"
		}

		httpHelpers.WriteOutput(w, map[string]any{"port": port, "address": workerHostname, "workerId": workerId.String()})
	}))

	// List all workers
	r.Handle("GET /workers", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// return empty array if no workers
		if len(workerMap) == 0 {
			httpHelpers.WriteOutput(w, []string{})
			return
		}

		var workerIds []string
		for key := range workerMap {
			workerIds = append(workerIds, key)
		}
		httpHelpers.WriteOutput(w, workerIds)
	}))

	// Get details of a specific worker
	r.Handle("GET /worker/{id}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		workerId, _ := url.PathUnescape(r.PathValue("id"))
		info := workerMap[workerId]
		if info == nil {
			httpHelpers.WriteError(w, http.StatusNotFound, "Worker not found")
			return
		}

		workerHostname := cfg.Spawner.Hostname
		if workerHostname == "" {
			workerHostname = "localhost"
		}

		alive := info.Process.ProcessState == nil

		output := map[string]any{
			"port":     info.Port,
			"address":  workerHostname,
			"workerId": workerId,
			"pid":      info.Process.Process.Pid,
			"alive":    alive,
		}

		if !alive {
			output["exitedCleanly"] = info.Process.ProcessState != nil && info.Process.ProcessState.Success()
		} else {
			isReachable := true
			start := time.Now()
			err := processHelpers.TestWorker(ctx, info.Port, 1*time.Second)
			elapsed := time.Since(start)
			if err != nil {
				slog.Error("Error connecting to worker", "error", err)
				isReachable = false
			} else {
				httpHelpers.WriteTimings(w, httpHelpers.Timings{"check-time": elapsed})
			}
			output["isReachable"] = isReachable
		}

		httpHelpers.WriteOutput(w, output)
	}))

	// Stop a specific worker
	r.Handle("DELETE /worker/{id}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		workerId, _ := url.PathUnescape(r.PathValue("id"))
		info := workerMap[workerId]
		if info == nil {
			httpHelpers.WriteError(w, http.StatusNotFound, "Worker not found")
			return
		}

		start := time.Now()
		err := info.Process.Process.Kill()
		elapsed := time.Since(start)

		if err != nil {
			slog.Error("Error stopping worker", "error", err)
			httpHelpers.WriteError(w, http.StatusInternalServerError, "Error stopping worker")
			return
		}
		delete(workerMap, workerId)

		httpHelpers.WriteTimings(w, httpHelpers.Timings{"stop-time": elapsed})
		httpHelpers.WriteOutput(w, map[string]any{"msg": "Worker stopped"})
	}))

	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.Spawner.Hostname, cfg.Spawner.Port),
		Handler: r,
	}
	// Run server in background
	go func() {
		slog.Info("Spawner listening", "hostname", cfg.Spawner.Hostname, "port", cfg.Spawner.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("ListenAndServe error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt
	<-ctx.Done()
	slog.Info("Signal received, shutting down...")

	for id, w := range workerMap {
		// If the worker is not running, skip it
		if w.Process != nil && w.Process.Process != nil {
			// First try a graceful shutdown
			err := w.Process.Process.Signal(syscall.SIGTERM)
			if err != nil {
				slog.Error("Error sending SIGTERM to process", "error", err)
				continue
			}

			// Wait for it to exit
			done := make(chan error, 1)
			go func() { done <- w.Process.Wait() }()

			select {
			case err := <-done:
				slog.Info("process exited", "error", err)
			case <-time.After(5 * time.Second):
				slog.Info("timeout, force killing")
				if err := w.Process.Process.Kill(); err != nil {
					slog.Error("Error force killing process", "error", err)
				}
				<-done // wait again to reap zombie
			}
		}
		delete(workerMap, id)
	}

	// Shutdown the HTTP server
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("HTTP server Shutdown error", "error", err)
	} else {
		slog.Info("HTTP server shut down gracefully")
	}
	cancel()

	// Wait a moment to ensure all logs are printed before exiting
	time.Sleep(1 * time.Second)

	slog.Info("Spawner exited gracefully")
}
