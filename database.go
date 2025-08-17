package main

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Database struct {
	db *sql.DB
}

type TLSFingerprint struct {
	ID            int
	ChromeVersion string
	RawResponse   string
	CollectedAt   time.Time
	CreatedAt     time.Time
}

// NewDatabase creates and initializes the SQLite database
func NewDatabase(dbPath string) (*Database, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Enable foreign keys and WAL mode for better performance
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
		return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
	}

	database := &Database{db: db}

	if err := database.createTables(); err != nil {
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	return database, nil
}

// createTables creates the database schema
func (d *Database) createTables() error {
	query := `CREATE TABLE IF NOT EXISTS tls_fingerprints (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		chrome_version TEXT NOT NULL,
		raw_response TEXT NOT NULL,
		collected_at DATETIME NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(chrome_version, collected_at)
	)`

	if _, err := d.db.Exec(query); err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}

	// Create indexes for better performance
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_fingerprints_version ON tls_fingerprints(chrome_version)`,
		`CREATE INDEX IF NOT EXISTS idx_fingerprints_collected ON tls_fingerprints(collected_at)`,
	}

	for _, index := range indexes {
		if _, err := d.db.Exec(index); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// SaveTLSFingerprint saves a TLS fingerprint to the database
func (d *Database) SaveTLSFingerprint(fingerprint *TLSFingerprint) error {
	_, err := d.db.Exec(`
		INSERT OR REPLACE INTO tls_fingerprints (
			chrome_version, raw_response, collected_at
		) VALUES (?, ?, ?)`,
		fingerprint.ChromeVersion,
		fingerprint.RawResponse,
		fingerprint.CollectedAt,
	)

	return err
}

// GetLatestFingerprint gets the most recent fingerprint for a specific Chrome version
func (d *Database) GetLatestFingerprint(chromeVersion string) (*TLSFingerprint, error) {
	var f TLSFingerprint
	err := d.db.QueryRow(`
		SELECT id, chrome_version, raw_response, collected_at, created_at
		FROM tls_fingerprints
		WHERE chrome_version = ?
		ORDER BY collected_at DESC
		LIMIT 1`, chromeVersion).Scan(&f.ID, &f.ChromeVersion, &f.RawResponse, &f.CollectedAt, &f.CreatedAt)

	if err != nil {
		return nil, err
	}

	return &f, nil
}

// GetFingerprintHistory gets fingerprint history for analysis
func (d *Database) GetFingerprintHistory(limit int) ([]TLSFingerprint, error) {
	rows, err := d.db.Query(`
		SELECT id, chrome_version, raw_response, collected_at, created_at
		FROM tls_fingerprints
		ORDER BY collected_at DESC
		LIMIT ?`, limit)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var fingerprints []TLSFingerprint
	for rows.Next() {
		var f TLSFingerprint
		err := rows.Scan(
			&f.ID, &f.ChromeVersion, &f.RawResponse, &f.CollectedAt, &f.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		fingerprints = append(fingerprints, f)
	}

	return fingerprints, nil
}

// Close closes the database connection
func (d *Database) Close() error {
	return d.db.Close()
}
