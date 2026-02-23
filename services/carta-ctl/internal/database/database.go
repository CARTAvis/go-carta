package database

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"unicode/utf8"

	"database/sql"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"embed"
	"encoding/json"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/auth"
	"github.com/CARTAvis/go-carta/services/carta-ctl/internal/session"
)

// Avoid needing to ship schema files separately
//
//go:embed schemas/preferences_schema_2.json
//go:embed schemas/layout_schema_2.json
//go:embed schemas/snippet_schema_1.json
//go:embed schemas/workspace_schema_1.json
var schemaFiles embed.FS

const PREFERENCE_SCHEMA_VERSION = 2
const LAYOUT_SCHEMA_VERSION = 2
const SNIPPET_SCHEMA_VERSION = 1
const WORKSPACE_SCHEMA_VERSION = 0

func loadSchema(c *jsonschema.Compiler, path string) (*jsonschema.Schema, error) {
	f, err := schemaFiles.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			slog.Error("error closing file %s: %v", path, err)
		}
	}()

	inst, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		slog.Error("Error unmarshalling JSON", "err", err)
	}
	if err := c.AddResource("embed://"+path, inst); err != nil {
		return nil, err
	}
	return c.Compile("embed://" + path)
}

type DbConfig struct {
	ConnString string
	db         *sqlx.DB

	// Compiled schemas
	PrefSchema      *jsonschema.Schema
	LayoutSchema    *jsonschema.Schema
	WorkspaceSchema *jsonschema.Schema
	SnippetSchema   *jsonschema.Schema
}

func (h *DbConfig) EnsureTables() error {
	schema := `
    CREATE TABLE IF NOT EXISTS preferences (
        username TEXT PRIMARY KEY,
        content  JSONB NOT NULL
    );

    CREATE TABLE IF NOT EXISTS layouts (
        name     TEXT NOT NULL,
        username TEXT NOT NULL,
        content  JSONB NOT NULL,
        PRIMARY KEY (name, username)
    );

    CREATE TABLE IF NOT EXISTS snippets (
        name     TEXT NOT NULL,
        username TEXT NOT NULL,
        content  JSONB NOT NULL,
        PRIMARY KEY (name, username)
    );

	CREATE TABLE IF NOT EXISTS workspaces (
		name     TEXT NOT NULL,
		username TEXT NOT NULL,
		id       UUID NOT NULL DEFAULT gen_random_uuid(),
		content  JSONB NOT NULL,

		-- Whether the workspace is shared with other users
		shared   BOOLEAN,

		-- Keep top-level 'id' out of the JSON content to avoid confusion
		CONSTRAINT no_top_level_id CHECK (NOT (content ? 'id')),

		-- But ensure it remains unique (if defined)
		CONSTRAINT unique_workspace_id UNIQUE (id),

		PRIMARY KEY (username, name)
	);

	CREATE INDEX IF NOT EXISTS idx_workspaces_username
    ON workspaces (username);
    `

	if _, err := h.db.Exec(schema); err != nil {
		return err
	}
	return nil
}

func (h *DbConfig) InitDb() {
	// Initialize DB connection
	db, err := sqlx.Connect("postgres", h.ConnString)
	if err != nil {
		slog.Error("Error connecting to database")
		os.Exit(-1)
	}
	h.db = db

	// Ensure tables exist
	if err := h.EnsureTables(); err != nil {
		slog.Error("Error ensuring database tables", "err", err)
		os.Exit(-1)
	}

	// Load JSON schemas
	c := jsonschema.NewCompiler()
	h.PrefSchema, err = loadSchema(c, "schemas/preferences_schema_2.json")
	if err != nil {
		slog.Error("Error loading preferences schema", "err", err)
		os.Exit(-1)
	}
	h.LayoutSchema, err = loadSchema(c, "schemas/layout_schema_2.json")
	if err != nil {
		slog.Error("Error loading layout schema", "err", err)
		os.Exit(-1)
	}
	h.SnippetSchema, err = loadSchema(c, "schemas/snippet_schema_1.json")
	if err != nil {
		slog.Error("Error loading snippet schema", "err", err)
		os.Exit(-1)
	}
	h.WorkspaceSchema, err = loadSchema(c, "schemas/workspace_schema_1.json")
	if err != nil {
		slog.Error("Error loading workspace schema", "err", err)
		os.Exit(-1)
	}
}

func getUsername(r *http.Request) string {
	ctx := r.Context()
	user, ok := ctx.Value(session.UserContextKey).(*auth.User)
	if !ok {
		slog.Error("No username found in request context")
		return ""
	}
	return user.Username
}

/*
func notImplemented(w http.ResponseWriter, r *http.Request) {
	slog.Warn(fmt.Sprintf("DB API called: %s %s (not implemented)", r.Method, r.URL.Path))
	w.WriteHeader(http.StatusNotImplemented)
	_, _ = w.Write([]byte("Not implemented"))
}
*/

func writeJSONResponse(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	resp := map[string]any{
		"status_code": status,
		"message":     message,
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("Error encoding JSON response", "err", err)
	}
}

func (h *DbConfig) handleGetPreferences(w http.ResponseWriter, r *http.Request) {
	slog.Debug(fmt.Sprintf("DB API called: %s %s", r.Method, r.URL.Path))

	user := getUsername(r)
	if user == "" {
		// No username means an error ... rather than unauthorized as `withAuth` should have caught this
		writeJSONResponse(w, http.StatusInternalServerError, "Username not found, but passed authorization")
		return
	}

	// Query DB
	var raw json.RawMessage
	err := h.db.GetContext(r.Context(), &raw,
		`SELECT content FROM preferences WHERE username = $1`,
		user,
	)
	var prefs map[string]any

	switch {
	case err == sql.ErrNoRows:
		// No preferences stored yet, return empty
		prefs = make(map[string]any)

	case err != nil:
		writeJSONResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to query preferences: %v", err))
		return

	default:
		// Decode JSONB from DB
		if err := json.Unmarshal(raw, &prefs); err != nil {
			slog.Warn("Error unmarshalling JSON in stored preferences", "err", err)
			writeJSONResponse(w, http.StatusInternalServerError, fmt.Sprintf("Malformed JSON in stored preferences: %v", err))
			return
		}

		// Validate
		if err := h.PrefSchema.Validate(prefs); err != nil {
			slog.Warn("Stored preferences failed validation", "err", err)
		}
	}

	// Respond
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"success":     true,
		"preferences": prefs,
	}); err != nil {
		slog.Error("Error encoding JSON response", "err", err)
	}
}

func (h *DbConfig) handleSetPreferences(w http.ResponseWriter, r *http.Request) {
	slog.Debug(fmt.Sprintf("DB API called: %s %s", r.Method, r.URL.Path))

	user := getUsername(r)
	if user == "" {
		// No username means an error ... rather than unauthorized as `withAuth` should have caught this
		writeJSONResponse(w, http.StatusInternalServerError, "Username not found, but passed authorization")
		return
	}

	// Decode JSON body
	var prefs map[string]any
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&prefs); err != nil {
		writeJSONResponse(w, http.StatusBadRequest, fmt.Sprintf("Failed to decode JSON body: %v", err))
		return
	}

	// Validate against schema
	prefs["version"] = PREFERENCE_SCHEMA_VERSION
	if err := h.PrefSchema.Validate(prefs); err != nil {
		writeJSONResponse(w, http.StatusBadRequest, fmt.Sprintf("Preferences validation failed: %v", err))
		return
	}

	// Remarshal the preferences to ensure proper JSONB format
	jsonBytes, err := json.Marshal(prefs)
	if err != nil {
		slog.Error("Error marshalling preferences", "err", err)
		writeJSONResponse(w, http.StatusInternalServerError, "Error marshalling preferences")
		return
	}

	// Persist to DB
	_, err = h.db.ExecContext(r.Context(),
		`INSERT INTO preferences (username, content)
        VALUES ($1, $2::jsonb)
        ON CONFLICT (username)
        DO UPDATE SET content = preferences.content || EXCLUDED.content`,
		user, jsonBytes,
	)
	if err != nil {
		writeJSONResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to store preferences: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	writeJSONResponse(w, http.StatusOK, "Preferences set successfully")
}

func (h *DbConfig) handleClearPreferences(w http.ResponseWriter, r *http.Request) {
	slog.Debug(fmt.Sprintf("DB API called: %s %s", r.Method, r.URL.Path))

	user := getUsername(r)
	if user == "" {
		writeJSONResponse(w, http.StatusInternalServerError, "Username not found, but passed authorization")
		return
	} else {
		slog.Debug("Clearing preferences for user", "user", user)
	}

	// Parse JSON body
	var body struct {
		Keys []string `json:"keys"`
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&body); err != nil {
		writeJSONResponse(w, http.StatusBadRequest, "Malformed JSON body")
		return
	}
	// Validate keys list
	if len(body.Keys) == 0 {
		slog.Debug("Malformed key list received for clearing preferences")
		writeJSONResponse(w, http.StatusBadRequest, "Malformed key list")
		return
	}

	slog.Debug("Clearing preference keys", "user", user, "keys", body.Keys)

	// Update DB to remove keys
	_, err := h.db.ExecContext(
		r.Context(),
		`UPDATE preferences
         SET content = content - $2::text[]
         WHERE username = $1`,
		user,
		pq.Array(body.Keys),
	)

	if err != nil {
		slog.Error("Error clearing preferences", "err", err)
		writeJSONResponse(w, http.StatusInternalServerError, "Problem clearing preferences")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"success": true,
	}); err != nil {
		slog.Error("Error encoding JSON response", "err", err)
	}
}

func (h *DbConfig) handleGetLayouts(w http.ResponseWriter, r *http.Request) {
	slog.Debug(fmt.Sprintf("DB API called: %s %s", r.Method, r.URL.Path))

	user := getUsername(r)
	if user == "" {
		writeJSONResponse(w, http.StatusInternalServerError, "Username not found, but passed authorization")
		return
	} else {
		slog.Debug("Getting layouts for user", "user", user)
	}

	// Query all layouts for this user
	rows, err := h.db.QueryContext(
		r.Context(),
		`SELECT name, content
         FROM layouts
         WHERE username = $1`,
		user,
	)
	if err != nil {
		slog.Error("DB error fetching layouts", "err", err)
		writeJSONResponse(w, http.StatusInternalServerError, "Failed to fetch layouts")
		return
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Warn("error closing rows", "err", err)
		}
	}()

	// Build the response map
	layouts := make(map[string]any)

	for rows.Next() {
		var name string
		var raw json.RawMessage

		if err := rows.Scan(&name, &raw); err != nil {
			slog.Error("Error scanning layout row", "err", err)
			continue
		}

		// Decode JSONB content
		var layout any
		if err := json.Unmarshal(raw, &layout); err != nil {
			slog.Warn("Error unmarshalling stored layout", "name", name, "err", err)
			continue
		}

		// Validate layout
		if err := h.LayoutSchema.Validate(layout); err != nil {
			slog.Warn("Returning invalid layout", "name", name, "err", err)
		}

		layouts[name] = layout
	}

	if err := rows.Err(); err != nil {
		slog.Error("Row iteration error", "err", err)
		writeJSONResponse(w, http.StatusInternalServerError, "Failed to read layouts")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"layouts": layouts,
	}); err != nil {
		slog.Error("Error encoding JSON response", "err", err)
	}
}

func (h *DbConfig) handleSetLayout(w http.ResponseWriter, r *http.Request) {
	slog.Debug(fmt.Sprintf("DB API called: %s %s", r.Method, r.URL.Path))

	user := getUsername(r)
	if user == "" {
		writeJSONResponse(w, http.StatusInternalServerError, "Username not found, but passed authorization")
		return
	} else {
		slog.Debug("Setting layout for user", "user", user)
	}

	// Parse JSON body
	var body struct {
		Name   string         `json:"layoutName"`
		Layout map[string]any `json:"layout"`
	}

	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&body); err != nil {
		writeJSONResponse(w, http.StatusBadRequest, "Malformed JSON body")
		return
	}

	version, ok := body.Layout["layoutVersion"].(float64)
	if body.Name == "" || body.Layout == nil || !ok || int(version) != LAYOUT_SCHEMA_VERSION {
		writeJSONResponse(w, http.StatusBadRequest, "Malformed layout update")
		return
	}

	// Validate layout
	if err := h.LayoutSchema.Validate(body.Layout); err != nil {
		slog.Warn("Layout validation failed", "name", body.Name, "err", err)
		writeJSONResponse(w, http.StatusBadRequest, fmt.Sprintf("Invalid layout update: %v", err))
		return
	}

	// Marshal layout to JSONB
	jsonBytes, err := json.Marshal(body.Layout)
	if err != nil {
		slog.Error("Error marshalling layout", "err", err)
		writeJSONResponse(w, http.StatusInternalServerError, "Error marshalling layout")
		return
	}

	// UPSERT into Postgres
	_, err = h.db.ExecContext(
		r.Context(),
		`INSERT INTO layouts (name, username, content)
         VALUES ($1, $2, $3::jsonb)
         ON CONFLICT (name, username)
         DO UPDATE SET content = EXCLUDED.content`,
		body.Name, user, jsonBytes,
	)

	if err != nil {
		slog.Error("Failed to store layout", "err", err)
		writeJSONResponse(w, http.StatusInternalServerError, "Failed to store layout")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"success": true,
	}); err != nil {
		slog.Error("Error encoding JSON response", "err", err)
	}
}

func (h *DbConfig) handleClearLayout(w http.ResponseWriter, r *http.Request) {
	slog.Debug(fmt.Sprintf("DB API called: %s %s", r.Method, r.URL.Path))

	user := getUsername(r)
	if user == "" {
		writeJSONResponse(w, http.StatusInternalServerError, "Username not found, but passed authorization")
		return
	} else {
		slog.Debug("Clearing layout for user", "user", user)
	}

	// Parse JSON body
	var body struct {
		LayoutName string `json:"layoutName"`
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&body); err != nil {
		writeJSONResponse(w, http.StatusBadRequest, "Malformed JSON body")
		return
	}
	// Validate layout name
	if body.LayoutName == "" {
		slog.Debug("Malformed layout name received for clearing layout")
		writeJSONResponse(w, http.StatusBadRequest, "Malformed layout name")
		return
	}

	slog.Debug("Clearing layout", "user", user, "layoutName", body.LayoutName)

	// Update DB to remove layout
	_, err := h.db.ExecContext(
		r.Context(),
		`DELETE FROM layouts
         WHERE name = $2 AND username = $1`,
		user,
		body.LayoutName,
	)

	if err != nil {
		slog.Error("Error removing layout", "err", err)
		writeJSONResponse(w, http.StatusInternalServerError, "Problem removing layout")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"success": true,
	}); err != nil {
		slog.Error("Error encoding JSON response", "err", err)
	}
}

func (h *DbConfig) handleGetSnippets(w http.ResponseWriter, r *http.Request) {
	slog.Debug(fmt.Sprintf("DB API called: %s %s", r.Method, r.URL.Path))

	user := getUsername(r)
	if user == "" {
		writeJSONResponse(w, http.StatusInternalServerError, "Username not found, but passed authorization")
		return
	} else {
		slog.Debug("Getting snippets for user", "user", user)
	}

	// Query all snippets for this user
	rows, err := h.db.QueryContext(
		r.Context(),
		`SELECT name, content
         FROM snippets
         WHERE username = $1`,
		user,
	)
	if err != nil {
		slog.Error("DB error fetching snippets", "err", err)
		writeJSONResponse(w, http.StatusInternalServerError, "Failed to fetch snippets")
		return
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Warn("error closing rows", "err", err)
		}
	}()

	// Build the response map
	snippets := make(map[string]any)

	for rows.Next() {
		var name string
		var raw json.RawMessage

		if err := rows.Scan(&name, &raw); err != nil {
			slog.Error("Error scanning snippet row", "err", err)
			continue
		}

		// Decode JSONB content
		var snippet any
		if err := json.Unmarshal(raw, &snippet); err != nil {
			slog.Warn("Error unmarshalling JSON in stored snippet", "name", name, "err", err)
			continue
		}

		// Validate snippet
		if err := h.SnippetSchema.Validate(snippet); err != nil {
			slog.Warn("Returning invalid snippet", "name", name, "err", err)
		}

		snippets[name] = snippet
	}

	if err := rows.Err(); err != nil {
		slog.Error("Row iteration error", "err", err)
		writeJSONResponse(w, http.StatusInternalServerError, "Failed to read snippets")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"success":  true,
		"snippets": snippets,
	}); err != nil {
		slog.Error("Error encoding JSON response", "err", err)
	}
}

func (h *DbConfig) handleSetSnippet(w http.ResponseWriter, r *http.Request) {
	slog.Debug(fmt.Sprintf("DB API called: %s %s", r.Method, r.URL.Path))

	user := getUsername(r)
	if user == "" {
		writeJSONResponse(w, http.StatusInternalServerError, "Username not found, but passed authorization")
		return
	} else {
		slog.Debug("Setting snippet for user", "user", user)
	}

	// Parse JSON body
	var body struct {
		Name    string         `json:"snippetName"`
		Snippet map[string]any `json:"snippet"`
	}

	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&body); err != nil {
		writeJSONResponse(w, http.StatusBadRequest, "Malformed JSON body")
		return
	}

	version, ok := body.Snippet["snippetVersion"].(float64)
	if body.Name == "" || body.Snippet == nil || !ok || int(version) != SNIPPET_SCHEMA_VERSION {
		writeJSONResponse(w, http.StatusBadRequest, "Malformed snippet update")
		return
	}

	// Validate snippet
	if err := h.SnippetSchema.Validate(body.Snippet); err != nil {
		slog.Warn("Snippet validation failed", "name", body.Name, "err", err)
		writeJSONResponse(w, http.StatusBadRequest, fmt.Sprintf("Invalid snippet update: %v", err))
		return
	}

	// Marshal snippet to JSONB
	jsonBytes, err := json.Marshal(body.Snippet)
	if err != nil {
		slog.Error("Error marshalling snippet", "err", err)
		writeJSONResponse(w, http.StatusInternalServerError, "Error marshalling snippet")
		return
	}

	// UPSERT into Postgres
	_, err = h.db.ExecContext(
		r.Context(),
		`INSERT INTO snippets (name, username, content)
         VALUES ($1, $2, $3::jsonb)
         ON CONFLICT (name, username)
         DO UPDATE SET content = EXCLUDED.content`,
		body.Name, user, jsonBytes,
	)

	if err != nil {
		slog.Error("Failed to store snippet", "err", err)
		writeJSONResponse(w, http.StatusInternalServerError, "Failed to store snippet")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"success": true,
	}); err != nil {
		slog.Error("Error encoding JSON response", "err", err)
	}
}

func (h *DbConfig) handleClearSnippet(w http.ResponseWriter, r *http.Request) {
	slog.Debug(fmt.Sprintf("DB API called: %s %s", r.Method, r.URL.Path))

	user := getUsername(r)
	if user == "" {
		writeJSONResponse(w, http.StatusInternalServerError, "Username not found, but passed authorization")
		return
	} else {
		slog.Debug("Clearing snippet for user", "user", user)
	}

	// Parse JSON body
	var body struct {
		SnippetName string `json:"snippetName"`
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&body); err != nil {
		writeJSONResponse(w, http.StatusBadRequest, "Malformed JSON body")
		return
	}
	// Validate snippet name
	if body.SnippetName == "" {
		slog.Debug("Malformed snippet name received for clearing snippet")
		writeJSONResponse(w, http.StatusBadRequest, "Malformed snippet name")
		return
	}

	slog.Debug("Clearing snippet", "user", user, "snippetName", body.SnippetName)

	// Update DB to remove snippet
	_, err := h.db.ExecContext(
		r.Context(),
		`DELETE FROM snippets
         WHERE name = $2 AND username = $1`,
		user,
		body.SnippetName,
	)

	if err != nil {
		slog.Error("Error removing snippet", "err", err)
		writeJSONResponse(w, http.StatusInternalServerError, "Problem removing snippet")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"success": true,
	}); err != nil {
		slog.Error("Error encoding JSON response", "err", err)
	}
}

func (h *DbConfig) handleGetWorkspaceByKey(w http.ResponseWriter, r *http.Request) {
	slog.Debug(fmt.Sprintf("DB API called: %s %s", r.Method, r.URL.Path))

	user := getUsername(r)
	if user == "" {
		// No username means an error ... rather than unauthorized as `withAuth` should have caught this
		writeJSONResponse(w, http.StatusInternalServerError, "Username not found, but passed authorization")
		return
	}

	key := r.PathValue("key")
	key, err := url.PathUnescape(key)
	if err != nil {
		writeJSONResponse(w, http.StatusBadRequest, "Invalid URL encoding")
		return
	}
	if key == "" {
		writeJSONResponse(w, http.StatusInternalServerError, "Missing key")
		return
	}
	if !utf8.ValidString(key) {
		writeJSONResponse(w, http.StatusBadRequest, "Invalid UTF-8 in workspace key")
		return
	}
	if key == "" {
		writeJSONResponse(w, http.StatusInternalServerError, "Missing key")
		return
	}

	// Query DB
	var row struct {
		Shared   sql.NullBool    `db:"shared"`
		Content  json.RawMessage `db:"content"`
		Editable bool            `db:"is_editable"`
	}
	err = h.db.GetContext(r.Context(), &row,
		`SELECT shared, content, (username = $2) AS is_editable FROM workspaces WHERE id = $1 AND (username = $2 OR shared = true)`,
		key,
		user,
	)
	var workspace map[string]any

	switch {
	case err == sql.ErrNoRows:
		slog.Debug("Workspace not found", "key", key)
		writeJSONResponse(w, http.StatusNotFound, fmt.Sprintf("Workspace not found: %v", key))
		return

	case err != nil:
		slog.Debug("Failed to query workspace", "key", key, "err", err)
		writeJSONResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to retrieve workspace: %v", key))
		return

	default:
		// Decode JSONB from DB
		if err := json.Unmarshal(row.Content, &workspace); err != nil {
			slog.Debug("Failed to decode stored workspace", "key", key, "err", err)
			writeJSONResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to decode stored workspace: %v", key))
			return
		}

		// Add ID and shared status to the workspace
		workspace["id"] = key
		workspace["editable"] = row.Editable
		if row.Shared.Valid {
			workspace["shared"] = row.Shared.Bool
		}

		// Validate
		if err := h.PrefSchema.Validate(workspace); err != nil {
			slog.Warn("Stored workspace failed validation", "key", key, "err", err)
			// Proceed anyway
		}
	}

	// Respond
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"success":   true,
		"workspace": workspace,
	}); err != nil {
		slog.Error("Error encoding JSON response", "err", err)
	}
}

func (h *DbConfig) handleGetWorkspaceByName(w http.ResponseWriter, r *http.Request) {
	slog.Debug(fmt.Sprintf("DB API called: %s %s", r.Method, r.URL.Path))

	user := getUsername(r)
	if user == "" {
		// No username means an error ... rather than unauthorized as `withAuth` should have caught this
		writeJSONResponse(w, http.StatusInternalServerError, "Username not found, but passed authorization")
		return
	}

	name := r.PathValue("name")
	name, err := url.PathUnescape(name)
	if err != nil {
		writeJSONResponse(w, http.StatusBadRequest, "Invalid URL encoding")
		return
	}
	if name == "" {
		writeJSONResponse(w, http.StatusInternalServerError, "Missing name")
		return
	}
	if !utf8.ValidString(name) {
		writeJSONResponse(w, http.StatusBadRequest, "Invalid UTF-8 in workspace name")
		return
	}

	// Query DB
	var row struct {
		ID      string          `db:"id"`
		Content json.RawMessage `db:"content"`
		Shared  sql.NullBool    `db:"shared"`
	}
	err = h.db.GetContext(r.Context(), &row,
		`SELECT id, content, shared FROM workspaces WHERE name = $1 AND username = $2`,
		name,
		user,
	)
	var workspace map[string]any

	switch {
	case err == sql.ErrNoRows:
		slog.Debug("Workspace not found", "name", name, "username", user)
		writeJSONResponse(w, http.StatusNotFound, fmt.Sprintf("Workspace not found: %v", name))
		return

	case err != nil:
		slog.Debug("Failed to query workspace", "name", name, "username", user, "err", err)
		writeJSONResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to retrieve workspace: %v", name))
		return

	default:
		// Decode JSONB from DB
		if err := json.Unmarshal(row.Content, &workspace); err != nil {
			slog.Debug("Failed to decode stored workspace", "name", name, "username", user, "err", err)
			writeJSONResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to decode stored workspace: %v", name))
			return
		}

		workspace["id"] = row.ID
		workspace["editable"] = true

		// Add shared status to workspace
		if row.Shared.Valid {
			workspace["shared"] = row.Shared.Bool
		}

		// Validate
		if err := h.PrefSchema.Validate(workspace); err != nil {
			slog.Warn("Stored workspace failed validation", "name", name, "username", user, "err", err)
			// Proceed anyway
		}
	}

	// Respond
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"success":   true,
		"workspace": workspace,
	}); err != nil {
		slog.Error("Error encoding JSON response", "err", err)
	}
}

func (h *DbConfig) handleSetWorkspace(w http.ResponseWriter, r *http.Request) {
	slog.Debug(fmt.Sprintf("DB API called: %s %s", r.Method, r.URL.Path))

	user := getUsername(r)
	if user == "" {
		writeJSONResponse(w, http.StatusInternalServerError, "Username not found, but passed authorization")
		return
	} else {
		slog.Debug("Setting workspace for user", "user", user)
	}

	// Parse JSON body
	var body struct {
		WorkspaceName string         `json:"workspaceName"`
		Workspace     map[string]any `json:"workspace"`
	}

	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&body); err != nil {
		writeJSONResponse(w, http.StatusBadRequest, "Malformed JSON body")
		return
	}

	version, ok := body.Workspace["workspaceVersion"].(float64)
	if body.WorkspaceName == "" || body.Workspace == nil || !ok || int(version) != WORKSPACE_SCHEMA_VERSION {
		writeJSONResponse(w, http.StatusBadRequest, "Malformed workspace update")
		return
	}

	// Validate workspace
	if err := h.WorkspaceSchema.Validate(body.Workspace); err != nil {
		slog.Warn("Workspace validation failed", "name", body.WorkspaceName, "err", err)
		writeJSONResponse(w, http.StatusBadRequest, fmt.Sprintf("Invalid workspace update: %v", err))
		return
	}

	// Separate out ID if present
	id, id_exists := body.Workspace["id"]
	if id_exists {
		delete(body.Workspace, "id")
	}
	shared, shared_exists := body.Workspace["shared"]
	if shared_exists {
		delete(body.Workspace, "shared")
	}

	// Marshal workspace to JSONB
	jsonBytes, err := json.Marshal(body.Workspace)
	if err != nil {
		slog.Error("Error marshalling workspace", "err", err)
		writeJSONResponse(w, http.StatusInternalServerError, "Error marshalling workspace")
		return
	}

	// UPSERT into Postgres
	if id_exists {
		_, err = h.db.ExecContext(
			r.Context(),
			`INSERT INTO workspaces (name, username, shared, id, content)
			VALUES ($1, $2, $3, $4, $5::jsonb)
			ON CONFLICT (name, username)
			DO UPDATE SET content = EXCLUDED.content, id = EXCLUDED.id, shared = EXCLUDED.shared`,
			body.WorkspaceName, user, shared, id, jsonBytes,
		)
	} else {
		err = h.db.QueryRowContext(
			r.Context(),
			`INSERT INTO workspaces (name, username, shared, content)
			VALUES ($1, $2, $3, $4::jsonb)
			ON CONFLICT (name, username)
			DO UPDATE SET content = EXCLUDED.content, shared = EXCLUDED.shared
			RETURNING id`,
			body.WorkspaceName, user, shared, jsonBytes,
		).Scan(&id)
	}

	if err != nil {
		slog.Error("Failed to store workspace", "err", err)
		writeJSONResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to store workspace: %v", err))
		return
	}

	body.Workspace["id"] = id
	body.Workspace["editable"] = true
	if shared_exists {
		body.Workspace["shared"] = shared
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"success":   true,
		"workspace": body.Workspace,
	}); err != nil {
		slog.Error("Error encoding JSON response", "err", err)
	}
}

func (h *DbConfig) handleListWorkspaces(w http.ResponseWriter, r *http.Request) {
	slog.Debug(fmt.Sprintf("DB API called: %s %s", r.Method, r.URL.Path))

	user := getUsername(r)
	if user == "" {
		// No username means an error ... rather than unauthorized as `withAuth` should have caught this
		writeJSONResponse(w, http.StatusInternalServerError, "Username not found, but passed authorization")
		return
	}

	// Query DB
	rows, err := h.db.QueryxContext(
		r.Context(),
		`SELECT name, id, content->>'date' AS date FROM workspaces WHERE username = $1`,
		user,
	)
	if err != nil {
		slog.Debug("Failed to query workspaces", "username", user, "err", err)
		writeJSONResponse(w, http.StatusInternalServerError, "Failed to retrieve workspaces")
		return
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Warn("error closing rows", "err", err)
		}
	}()

	workspaces := make([]map[string]any, 0)

	for rows.Next() {
		var (
			name string
			id   string
			date sql.NullString
		)

		if err := rows.Scan(&name, &id, &date); err != nil {
			slog.Error("Error scanning workspace row", "err", err)
			continue
		}

		if date.Valid {
			workspaces = append(workspaces, map[string]any{
				"id":   id,
				"date": date.String,
				"name": name,
			})
		} else {
			workspaces = append(workspaces, map[string]any{
				"id":   id,
				"name": name,
			})
		}
	}

	if err := rows.Err(); err != nil {
		slog.Error("Row iteration error", "err", err)
		writeJSONResponse(w, http.StatusInternalServerError, "Failed to read workspaces")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"success":    true,
		"workspaces": workspaces,
	}); err != nil {
		slog.Error("Error encoding JSON response", "err", err)
	}
}

func (h *DbConfig) handleClearWorkspace(w http.ResponseWriter, r *http.Request) {
	slog.Debug(fmt.Sprintf("DB API called: %s %s", r.Method, r.URL.Path))

	user := getUsername(r)
	if user == "" {
		writeJSONResponse(w, http.StatusInternalServerError, "Username not found, but passed authorization")
		return
	} else {
		slog.Debug("Clearing workspace for user", "user", user)
	}

	// Parse JSON body
	// deletion by workspace ID is listed as TBD in the typescript controller
	var body struct {
		WorkspaceName string `json:"workspaceName"`
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&body); err != nil {
		writeJSONResponse(w, http.StatusBadRequest, "Malformed JSON body")
		return
	}
	// Validate workspace name
	if body.WorkspaceName == "" {
		slog.Debug("Malformed workspace name received for clearing workspace")
		writeJSONResponse(w, http.StatusBadRequest, "Malformed workspace name")
		return
	}

	slog.Debug("Clearing workspace", "user", user, "workspaceName", body.WorkspaceName)

	// Update DB to remove workspace
	_, err := h.db.ExecContext(
		r.Context(),
		`DELETE FROM workspaces
         WHERE name = $2 AND username = $1`,
		user,
		body.WorkspaceName,
	)

	if err != nil {
		slog.Error("Error removing workspace", "err", err)
		writeJSONResponse(w, http.StatusInternalServerError, "Problem removing workspace")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"success": true,
	}); err != nil {
		slog.Error("Error encoding JSON response", "err", err)
	}
}

func (h *DbConfig) handleShareWorkspace(w http.ResponseWriter, r *http.Request) {
	slog.Debug(fmt.Sprintf("DB API called: %s %s", r.Method, r.URL.Path))

	user := getUsername(r)
	if user == "" {
		writeJSONResponse(w, http.StatusInternalServerError, "Username not found, but passed authorization")
		return
	} else {
		slog.Debug("Sharing workspace for user", "user", user)
	}

	workspaceID := r.PathValue("id")
	workspaceID, err := url.PathUnescape(workspaceID)
	if err != nil {
		writeJSONResponse(w, http.StatusBadRequest, "Invalid URL encoding")
		return
	}
	if !utf8.ValidString(workspaceID) {
		writeJSONResponse(w, http.StatusBadRequest, "Invalid UTF-8 in workspace ID")
		return
	}
	if workspaceID == "" {
		writeJSONResponse(w, http.StatusBadRequest, "Missing workspace ID")
		return
	}

	// Update DB to set shared = true
	result, err := h.db.ExecContext(
		r.Context(),
		`UPDATE workspaces
		 SET shared = true
		 WHERE id = $1 AND username = $2`,
		workspaceID, user,
	)

	if err != nil {
		slog.Error("Error sharing workspace", "err", err)
		writeJSONResponse(w, http.StatusInternalServerError, "Problem sharing workspace")
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		slog.Error("Error getting rows affected for sharing workspace", "err", err)
		writeJSONResponse(w, http.StatusInternalServerError, "Problem sharing workspace")
		return
	}

	if rowsAffected == 0 {
		slog.Debug("No workspace found to share", "workspaceID", workspaceID, "user", user)
		writeJSONResponse(w, http.StatusNotFound, "Workspace not found or not owned by user")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"success":  true,
		"shareKey": workspaceID,
		"id":       workspaceID,
	}); err != nil {
		slog.Error("Error encoding JSON response", "err", err)
	}
}

func (h *DbConfig) Router() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("GET /preferences", http.HandlerFunc(h.handleGetPreferences))
	mux.Handle("PUT /preferences", http.HandlerFunc(h.handleSetPreferences))
	mux.Handle("DELETE /preferences", http.HandlerFunc(h.handleClearPreferences))

	mux.Handle("GET /layouts", http.HandlerFunc(h.handleGetLayouts))
	mux.Handle("PUT /layout", http.HandlerFunc(h.handleSetLayout))
	mux.Handle("DELETE /layout", http.HandlerFunc(h.handleClearLayout))

	mux.Handle("GET /snippets", http.HandlerFunc(h.handleGetSnippets))
	mux.Handle("PUT /snippet", http.HandlerFunc(h.handleSetSnippet))
	mux.Handle("DELETE /snippet", http.HandlerFunc(h.handleClearSnippet))

	mux.Handle("POST /share/workspace/{id}", http.HandlerFunc(h.handleShareWorkspace))

	mux.Handle("GET /list/workspaces", http.HandlerFunc(h.handleListWorkspaces))
	mux.Handle("GET /workspace/key/{key}", http.HandlerFunc(h.handleGetWorkspaceByKey))
	mux.Handle("GET /workspace/{name}", http.HandlerFunc(h.handleGetWorkspaceByName))
	mux.Handle("PUT /workspace", http.HandlerFunc(h.handleSetWorkspace))
	mux.Handle("DELETE /workspace", http.HandlerFunc(h.handleClearWorkspace))

	return mux
}
