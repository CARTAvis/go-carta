package database

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log/slog"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

// Migrations are embedded so the controller does not need to ship SQL files
// separately.
//
//go:embed migrations/*.sql
var migrationFiles embed.FS

const migrationsPath = "migrations"

// EnsureTables applies any outstanding schema migrations.
//
// The migration driver uses a single connection so that golang-migrate's
// advisory lock serialises controllers that start at the same time. Existing
// databases that predate the migration table are handled by the idempotent
// baseline migration, which uses CREATE TABLE IF NOT EXISTS.
func (h *DbConfig) EnsureTables() error {
	ctx := context.Background()

	conn, err := h.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("opening migration connection: %w", err)
	}

	driver, err := postgres.WithConnection(ctx, conn, &postgres.Config{})
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("creating migration database driver: %w", err)
	}

	source, err := iofs.New(migrationFiles, migrationsPath)
	if err != nil {
		_ = driver.Close()
		return fmt.Errorf("loading migrations: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", source, "postgres", driver)
	if err != nil {
		_ = source.Close()
		_ = driver.Close()
		return fmt.Errorf("creating migration runner: %w", err)
	}
	defer func() {
		if sourceErr, databaseErr := m.Close(); sourceErr != nil || databaseErr != nil {
			slog.Warn("Error closing migration runner", "source_err", sourceErr, "database_err", databaseErr)
		}
	}()

	err = m.Up()
	if errors.Is(err, migrate.ErrNoChange) {
		slog.Debug("Database schema is already up to date")
		return nil
	}
	if err != nil {
		return fmt.Errorf("applying schema migrations: %w", err)
	}

	// Up returns nil only when at least one migration was applied.
	version, dirty, versionErr := m.Version()
	if versionErr != nil {
		slog.Info("Applied database schema migrations", "version_err", versionErr)
	} else {
		slog.Info("Applied database schema migrations", "version", version, "dirty", dirty)
	}
	return nil
}
