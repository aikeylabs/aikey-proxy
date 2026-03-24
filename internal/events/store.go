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
	_, err := db.Exec(`
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
	`)
	return err
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
			 duration_ms, status_code, is_streaming, error_type, request_path)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
