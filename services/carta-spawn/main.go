package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/pflag"

	"github.com/CARTAvis/go-carta/pkg/config"
	helpers "github.com/CARTAvis/go-carta/pkg/shared"
	"github.com/CARTAvis/go-carta/services/carta-spawn/internal/httpHelpers"
	"github.com/CARTAvis/go-carta/services/carta-spawn/internal/processHelpers"
)

// workerRegistry tracks running workers. Handlers run concurrently, so all
// access goes through the mutex.
type workerRegistry struct {
	mu      sync.Mutex
	workers map[string]*processHelpers.Worker
}

func newWorkerRegistry() *workerRegistry {
	return &workerRegistry{workers: make(map[string]*processHelpers.Worker)}
}

func (r *workerRegistry) add(id string, w *processHelpers.Worker) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.workers[id] = w
}

func (r *workerRegistry) get(id string) *processHelpers.Worker {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.workers[id]
}

// remove unregisters a worker and returns it, or nil if another caller took
// it first, so only one caller ever stops a given worker.
func (r *workerRegistry) remove(id string) *processHelpers.Worker {
	r.mu.Lock()
	defer r.mu.Unlock()
	w, ok := r.workers[id]
	if !ok {
		return nil
	}
	delete(r.workers, id)
	return w
}

func (r *workerRegistry) ids() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]string, 0, len(r.workers))
	for id := range r.workers {
		ids = append(ids, id)
	}
	return ids
}

func (r *workerRegistry) takeAll() map[string]*processHelpers.Worker {
	r.mu.Lock()
	defer r.mu.Unlock()
	workers := r.workers
	r.workers = make(map[string]*processHelpers.Worker)
	return workers
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
	pflag.String("base_dir", "", "Starting directory for data")
	pflag.String("top_level_dir", "", "Top-level directory for data")
	pflag.Int("timeout", 5, "Spawn timeout in seconds")
	pflag.Bool("run_as_current_user", false, "Launch the worker directly as the spawner's own user instead of sudo-ing to the requested user")
	pflag.String("override", "", "Override simple config values (string, int, bool) as comma-separated key:value pairs (e.g., spawner.port:9000,log_level:debug)")

	pflag.Parse()

	config.BindFlags(map[string]string{
		"log_level":           "log_level",
		"port":                "spawner.port",
		"hostname":            "spawner.hostname",
		"worker_exec":         "spawner.worker_exec",
		"timeout":             "spawner.timeout",
		"base_dir":            "spawner.base_dir",
		"top_level_dir":       "spawner.top_level_dir",
		"run_as_current_user": "spawner.run_as_current_user",
	})

	cfg := config.Load(pflag.Lookup("config").Value.String(), pflag.Lookup("override").Value.String())

	// Update the logger to use the configured log level
	logger = helpers.NewLogger("carta-spawn", cfg.LogLevel)
	slog.SetDefault(logger)

	// Global context that cancels all spawned processes on SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	registry := newWorkerRegistry()

	workerHostname := cfg.Spawner.Hostname
	if workerHostname == "" {
		workerHostname = "localhost"
	}

	r := http.NewServeMux()

	// Start a new worker
	r.Handle("POST /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()

		// parse the username from the request body
		var reqBody struct {
			Username string `json:"username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			slog.Error("Error decoding request body", "error", err)
			httpHelpers.WriteError(w, http.StatusBadRequest, "Error decoding request body")
			return
		}

		slog.Info("Process started", "username", reqBody.Username)

		worker, err := processHelpers.SpawnWorker(ctx, cfg.Spawner, reqBody.Username)
		spawnerDuration := time.Since(startTime)
		if err != nil {
			slog.Error("Error spawning worker on free port", "error", err)
			httpHelpers.WriteError(w, http.StatusInternalServerError, "Error spawning worker")
			return
		}
		slog.Info("Started worker", "port", worker.Port)

		startTime = time.Now()
		err = processHelpers.TestWorker(ctx, worker.Port, 2*time.Second)
		testWorkerDuration := time.Since(startTime)
		if err != nil {
			slog.Error("Error connecting to worker", "error", err)
			if err := worker.Kill(); err != nil {
				slog.Error("Error killing worker", "error", err)
			}
			httpHelpers.WriteError(w, http.StatusInternalServerError, "Error connecting to worker")
			return
		}
		slog.Info("Connected to worker", "port", worker.Port)
		workerId := uuid.New()
		registry.add(workerId.String(), worker)
		httpHelpers.WriteTimings(w, httpHelpers.Timings{"spawn-time": spawnerDuration, "check-time": testWorkerDuration})

		httpHelpers.WriteOutput(w, map[string]any{"port": worker.Port, "address": workerHostname, "workerId": workerId.String()})
	}))

	// List all workers
	r.Handle("GET /workers", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpHelpers.WriteOutput(w, registry.ids())
	}))

	// Get details of a specific worker
	r.Handle("GET /worker/{id}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		workerId, _ := url.PathUnescape(r.PathValue("id"))
		worker := registry.get(workerId)
		if worker == nil {
			httpHelpers.WriteError(w, http.StatusNotFound, "Worker not found")
			return
		}

		alive := worker.Alive()

		output := map[string]any{
			"port":     worker.Port,
			"address":  workerHostname,
			"workerId": workerId,
			"pid":      worker.Pid(),
			"alive":    alive,
		}

		if !alive {
			output["exitedCleanly"] = worker.ExitedCleanly()
		} else {
			isReachable := true
			start := time.Now()
			err := processHelpers.TestWorker(ctx, worker.Port, 1*time.Second)
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
		// Removing first makes this the only caller that stops the worker.
		worker := registry.remove(workerId)
		if worker == nil {
			httpHelpers.WriteError(w, http.StatusNotFound, "Worker not found")
			return
		}

		start := time.Now()
		err := worker.Kill()
		elapsed := time.Since(start)

		if err != nil {
			slog.Error("Error stopping worker", "error", err)
			registry.add(workerId, worker)
			httpHelpers.WriteError(w, http.StatusInternalServerError, "Error stopping worker")
			return
		}

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

	var stopping sync.WaitGroup
	for id, worker := range registry.takeAll() {
		stopping.Add(1)
		go func() {
			defer stopping.Done()
			if err := worker.Stop(5 * time.Second); err != nil {
				slog.Error("Error stopping worker", "workerId", id, "error", err)
			}
		}()
	}
	stopping.Wait()

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
