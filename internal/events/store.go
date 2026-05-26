package events

import (
	"database/sql"
	"fmt"
	"log/slog"

	_ "modernc.org/sqlite"
)

// Store provides SQLite-backed storage for usage events.
type Store struct {
	db *sql.DB
}

// OpenStore opens (or creates) the events database with WAL mode.
func OpenStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open events db: %w", err)
	}

	// Enable WAL for concurrent read/write.
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}

	// Create table if not exists.
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate events db: %w", err)
	}

	slog.Info("events store opened", "path", dbPath)
	return &Store{db: db}, nil
}

func migrate(db *sql.DB) error {
	// Why per-statement Exec (not one big batch): we want partial-state
	// safety — if the App-pipeline columns ALTERs (idempotent guards
	// further down) fail individually we can investigate without rolling
	// back the baseline.
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS usage_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp INTEGER NOT NULL,
			virtual_key_id TEXT NOT NULL,
			provider TEXT NOT NULL,
			model TEXT DEFAULT '',
			input_tokens INTEGER DEFAULT 0,
			output_tokens INTEGER DEFAULT 0,
			duration_ms INTEGER NOT NULL,
			status_code INTEGER NOT NULL,
			is_streaming INTEGER NOT NULL DEFAULT 0,
			error_type TEXT DEFAULT '',
			request_path TEXT NOT NULL,
			created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
		);
		CREATE INDEX IF NOT EXISTS idx_events_timestamp ON usage_events(timestamp);
		CREATE INDEX IF NOT EXISTS idx_events_vkey ON usage_events(virtual_key_id);
	`); err != nil {
		return err
	}

	// Phase 4 (AKL-207) — add App pipeline audit columns. SQLite has no
	// `ADD COLUMN IF NOT EXISTS`, so we probe pragma_table_info and skip
	// when the column already exists (idempotent for re-opening an
	// existing DB).
	appCols := []struct{ name, ddl string }{
		{"app_slug", "ALTER TABLE usage_events ADD COLUMN app_slug TEXT DEFAULT ''"},
		{"app_key_id", "ALTER TABLE usage_events ADD COLUMN app_key_id TEXT DEFAULT ''"},
		{"app_mode", "ALTER TABLE usage_events ADD COLUMN app_mode TEXT DEFAULT ''"},
		{"bound_via", "ALTER TABLE usage_events ADD COLUMN bound_via TEXT DEFAULT ''"},
		{"requested_model", "ALTER TABLE usage_events ADD COLUMN requested_model TEXT DEFAULT ''"},
		{"resolved_provider", "ALTER TABLE usage_events ADD COLUMN resolved_provider TEXT DEFAULT ''"},
		// v1.0.0-rc.6: session_id for Performance Top N sessions chart.
		// Same idempotent-ADD-with-pragma-probe pattern as the rest;
		// new column lives at end of the table to keep INSERT ordering
		// of pre-existing columns stable.
		{"session_id", "ALTER TABLE usage_events ADD COLUMN session_id TEXT DEFAULT ''"},
	}
	for _, c := range appCols {
		var count int
		if err := db.QueryRow(
			"SELECT COUNT(*) FROM pragma_table_info('usage_events') WHERE name=?", c.name,
		).Scan(&count); err != nil {
			return fmt.Errorf("probe %s: %w", c.name, err)
		}
		if count > 0 {
			continue
		}
		if _, err := db.Exec(c.ddl); err != nil {
			return fmt.Errorf("add %s: %w", c.name, err)
		}
	}
	// Per-app index for the most common dashboard query ("usage by app").
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_app_slug ON usage_events(app_slug) WHERE app_slug != ''`); err != nil {
		return err
	}
	return nil
}

// Insert writes a batch of events to the database.
func (s *Store) Insert(events []UsageEvent) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO usage_events
			(timestamp, virtual_key_id, provider, model, input_tokens, output_tokens,
			 duration_ms, status_code, is_streaming, error_type, request_path,
			 app_slug, app_key_id, app_mode, bound_via, requested_model, resolved_provider,
			 session_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()

	for _, e := range events {
		streaming := 0
		if e.IsStreaming {
			streaming = 1
		}
		_, err := stmt.Exec(
			e.Timestamp.Unix(),
			e.VirtualKeyID,
			e.Provider,
			e.Model,
			e.InputTokens,
			e.OutputTokens,
			e.DurationMs,
			e.StatusCode,
			streaming,
			e.ErrorType,
			e.RequestPath,
			e.AppSlug,
			e.AppKeyID,
			e.AppMode,
			e.BoundVia,
			e.RequestedModel,
			e.ResolvedProvider,
			e.SessionID,
		)
		if err != nil {
			return fmt.Errorf("insert event: %w", err)
		}
	}

	return tx.Commit()
}

// QueryStats returns aggregated stats for admin metrics.
func (s *Store) QueryStats() (map[string]int64, map[string]int64, error) {
	byVKey := make(map[string]int64)
	byProvider := make(map[string]int64)

	rows, err := s.db.Query("SELECT virtual_key_id, COUNT(*) FROM usage_events GROUP BY virtual_key_id")
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var count int64
		rows.Scan(&key, &count)
		byVKey[key] = count
	}

	rows2, err := s.db.Query("SELECT provider, COUNT(*) FROM usage_events GROUP BY provider")
	if err != nil {
		return nil, nil, err
	}
	defer rows2.Close()
	for rows2.Next() {
		var prov string
		var count int64
		rows2.Scan(&prov, &count)
		byProvider[prov] = count
	}

	return byVKey, byProvider, nil
}

// Close closes the database.
func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
