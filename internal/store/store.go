package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/lainsmain/mneme-server/internal/auth"
)

var (
	objectHashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	deviceIDPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

type Store struct {
	db         *sql.DB
	objectsDir string
	mutationMu sync.Mutex
}

type Token struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"createdAt"`
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
}

type Manifest struct {
	DeviceID           string    `json:"deviceId"`
	Revision           int64     `json:"revision"`
	ObjectHash         string    `json:"objectHash"`
	UpdatedAt          time.Time `json:"updatedAt"`
	ReferencesComplete bool      `json:"referencesComplete"`
}

type StorageStats struct {
	ObjectCount             int64 `json:"objectCount"`
	ObjectBytes             int64 `json:"objectBytes"`
	ManifestHistoryCount    int64 `json:"manifestHistoryCount"`
	CompleteManifestCount   int64 `json:"completeManifestCount"`
	IncompleteManifestCount int64 `json:"incompleteManifestCount"`
}

type GarbageCollectionResult struct {
	PrunedManifestCount int64        `json:"prunedManifestCount"`
	DeletedObjectCount  int64        `json:"deletedObjectCount"`
	ReclaimedBytes      int64        `json:"reclaimedBytes"`
	Storage             StorageStats `json:"storage"`
}

func Open(dataDirectory string) (*Store, error) {
	if err := os.MkdirAll(dataDirectory, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	objectsDir := filepath.Join(dataDirectory, "objects")
	if err := os.MkdirAll(objectsDir, 0o700); err != nil {
		return nil, fmt.Errorf("create objects directory: %w", err)
	}

	db, err := sql.Open("sqlite", filepath.Join(dataDirectory, "mneme.db"))
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, objectsDir: objectsDir}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	statements := []string{
		`PRAGMA journal_mode = WAL`,
		`PRAGMA foreign_keys = ON`,
		`PRAGMA busy_timeout = 5000`,
		`CREATE TABLE IF NOT EXISTS tokens (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			salt BLOB NOT NULL,
			secret_hash BLOB NOT NULL,
			created_at INTEGER NOT NULL,
			revoked_at INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS objects (
			hash TEXT PRIMARY KEY,
			size INTEGER NOT NULL,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS manifests (
			device_id TEXT PRIMARY KEY,
			revision INTEGER NOT NULL,
			object_hash TEXT NOT NULL REFERENCES objects(hash),
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS manifest_history (
			device_id TEXT NOT NULL,
			revision INTEGER NOT NULL,
			object_hash TEXT NOT NULL REFERENCES objects(hash),
			updated_at INTEGER NOT NULL,
			references_complete INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY(device_id, revision)
		)`,
		`CREATE TABLE IF NOT EXISTS manifest_objects (
			device_id TEXT NOT NULL,
			revision INTEGER NOT NULL,
			object_hash TEXT NOT NULL REFERENCES objects(hash),
			PRIMARY KEY(device_id, revision, object_hash),
			FOREIGN KEY(device_id, revision) REFERENCES manifest_history(device_id, revision) ON DELETE CASCADE
		)`,
		`INSERT OR IGNORE INTO manifest_history(device_id, revision, object_hash, updated_at, references_complete)
			SELECT device_id, revision, object_hash, updated_at, 0 FROM manifests`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate database: %w", err)
		}
	}
	return nil
}

func (s *Store) CreateToken(ctx context.Context, name string) (string, Token, error) {
	plain, parts, err := auth.Generate()
	if err != nil {
		return "", Token{}, err
	}
	salt, err := auth.NewSalt()
	if err != nil {
		return "", Token{}, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO tokens(id, name, salt, secret_hash, created_at) VALUES(?, ?, ?, ?, ?)`,
		parts.ID, name, salt, auth.Hash(parts.Secret, salt), now.UnixMilli(),
	)
	if err != nil {
		return "", Token{}, fmt.Errorf("store token: %w", err)
	}
	return plain, Token{ID: parts.ID, Name: name, CreatedAt: now}, nil
}

func (s *Store) Authenticate(ctx context.Context, plain string) (Token, bool) {
	parts, err := auth.Parse(plain)
	if err != nil {
		return Token{}, false
	}
	var token Token
	var salt, expected []byte
	var createdAt int64
	err = s.db.QueryRowContext(ctx,
		`SELECT id, name, salt, secret_hash, created_at FROM tokens WHERE id = ? AND revoked_at IS NULL`,
		parts.ID,
	).Scan(&token.ID, &token.Name, &salt, &expected, &createdAt)
	if err != nil || !auth.Matches(parts.Secret, salt, expected) {
		return Token{}, false
	}
	token.CreatedAt = time.UnixMilli(createdAt).UTC()
	return token, true
}

func (s *Store) ListTokens(ctx context.Context) ([]Token, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, created_at, revoked_at FROM tokens ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("list tokens: %w", err)
	}
	defer rows.Close()
	var tokens []Token
	for rows.Next() {
		var token Token
		var createdAt int64
		var revokedAt sql.NullInt64
		if err := rows.Scan(&token.ID, &token.Name, &createdAt, &revokedAt); err != nil {
			return nil, err
		}
		token.CreatedAt = time.UnixMilli(createdAt).UTC()
		if revokedAt.Valid {
			value := time.UnixMilli(revokedAt.Int64).UTC()
			token.RevokedAt = &value
		}
		tokens = append(tokens, token)
	}
	return tokens, rows.Err()
}

func (s *Store) RevokeToken(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, time.Now().UTC().UnixMilli(), id)
	if err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return errors.New("active token not found")
	}
	return nil
}

func (s *Store) PutObject(ctx context.Context, expectedHash string, source io.Reader, maxBytes int64) (int64, error) {
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	if !objectHashPattern.MatchString(expectedHash) {
		return 0, errors.New("object hash must be 64 lowercase hexadecimal characters")
	}
	path := s.objectPath(expectedHash)
	if info, err := os.Stat(path); err == nil {
		_, dbErr := s.db.ExecContext(ctx,
			`INSERT INTO objects(hash, size, created_at) VALUES(?, ?, ?) ON CONFLICT(hash) DO NOTHING`,
			expectedHash, info.Size(), time.Now().UTC().UnixMilli(),
		)
		if dbErr != nil {
			return 0, dbErr
		}
		return info.Size(), nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return 0, err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".upload-*")
	if err != nil {
		return 0, err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)

	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(temporary, hasher), io.LimitReader(source, maxBytes+1))
	closeErr := temporary.Close()
	if copyErr != nil {
		return 0, copyErr
	}
	if closeErr != nil {
		return 0, closeErr
	}
	if written > maxBytes {
		return 0, errors.New("object exceeds configured size limit")
	}
	if actual := hex.EncodeToString(hasher.Sum(nil)); actual != expectedHash {
		return 0, fmt.Errorf("object hash mismatch: got %s", actual)
	}
	if err := os.Chmod(temporaryName, 0o600); err != nil {
		return 0, err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return 0, err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO objects(hash, size, created_at) VALUES(?, ?, ?) ON CONFLICT(hash) DO NOTHING`,
		expectedHash, written, time.Now().UTC().UnixMilli(),
	)
	return written, err
}

func (s *Store) OpenObject(hash string) (*os.File, error) {
	if !objectHashPattern.MatchString(hash) {
		return nil, os.ErrNotExist
	}
	return os.Open(s.objectPath(hash))
}

func (s *Store) PutManifest(ctx context.Context, deviceID string, revision int64, objectHash string) error {
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	if !deviceIDPattern.MatchString(deviceID) {
		return errors.New("invalid device id")
	}
	if revision < 1 || !objectHashPattern.MatchString(objectHash) {
		return errors.New("invalid manifest")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().UnixMilli()
	result, err := tx.ExecContext(ctx, `
		INSERT INTO manifest_history(device_id, revision, object_hash, updated_at, references_complete)
		VALUES(?, ?, ?, ?, 0) ON CONFLICT(device_id, revision) DO NOTHING`,
		deviceID, revision, objectHash, now,
	)
	if err != nil {
		return fmt.Errorf("store manifest history: %w", err)
	}
	inserted, _ := result.RowsAffected()
	if inserted == 0 {
		var existingHash string
		if err := tx.QueryRowContext(ctx,
			`SELECT object_hash FROM manifest_history WHERE device_id = ? AND revision = ?`,
			deviceID, revision,
		).Scan(&existingHash); err != nil || existingHash != objectHash {
			return errors.New("manifest revision already exists with different content")
		}
	}
	result, err = tx.ExecContext(ctx, `
		INSERT INTO manifests(device_id, revision, object_hash, updated_at) VALUES(?, ?, ?, ?)
		ON CONFLICT(device_id) DO UPDATE SET
			revision = excluded.revision,
			object_hash = excluded.object_hash,
			updated_at = excluded.updated_at
		WHERE excluded.revision >= manifests.revision`,
		deviceID, revision, objectHash, now,
	)
	if err != nil {
		return fmt.Errorf("store manifest: %w", err)
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return errors.New("manifest revision is older than the stored revision")
	}
	return tx.Commit()
}

func (s *Store) Manifest(ctx context.Context, deviceID string) (Manifest, error) {
	if !deviceIDPattern.MatchString(deviceID) {
		return Manifest{}, sql.ErrNoRows
	}
	var value Manifest
	var updatedAt int64
	err := s.db.QueryRowContext(ctx,
		`SELECT manifest.device_id, manifest.revision, manifest.object_hash, manifest.updated_at,
			COALESCE(history.references_complete, 0)
		 FROM manifests AS manifest
		 LEFT JOIN manifest_history AS history
		   ON history.device_id = manifest.device_id AND history.revision = manifest.revision
		 WHERE manifest.device_id = ?`,
		deviceID,
	).Scan(&value.DeviceID, &value.Revision, &value.ObjectHash, &updatedAt, &value.ReferencesComplete)
	value.UpdatedAt = time.UnixMilli(updatedAt).UTC()
	return value, err
}

func (s *Store) ListManifests(ctx context.Context) ([]Manifest, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT manifest.device_id, manifest.revision, manifest.object_hash, manifest.updated_at,
			COALESCE(history.references_complete, 0)
		FROM manifests AS manifest
		LEFT JOIN manifest_history AS history
		  ON history.device_id = manifest.device_id AND history.revision = manifest.revision
		ORDER BY manifest.device_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var manifests []Manifest
	for rows.Next() {
		var value Manifest
		var updatedAt int64
		if err := rows.Scan(&value.DeviceID, &value.Revision, &value.ObjectHash, &updatedAt, &value.ReferencesComplete); err != nil {
			return nil, err
		}
		value.UpdatedAt = time.UnixMilli(updatedAt).UTC()
		manifests = append(manifests, value)
	}
	return manifests, rows.Err()
}

func (s *Store) ListManifestHistory(ctx context.Context, deviceID string, limit int) ([]Manifest, error) {
	if !deviceIDPattern.MatchString(deviceID) {
		return nil, errors.New("invalid device id")
	}
	if limit < 1 || limit > 365 {
		limit = 30
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT device_id, revision, object_hash, updated_at, references_complete
		FROM manifest_history WHERE device_id = ? ORDER BY revision DESC LIMIT ?`, deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var manifests []Manifest
	for rows.Next() {
		var value Manifest
		var updatedAt int64
		if err := rows.Scan(
			&value.DeviceID, &value.Revision, &value.ObjectHash, &updatedAt, &value.ReferencesComplete,
		); err != nil {
			return nil, err
		}
		value.UpdatedAt = time.UnixMilli(updatedAt).UTC()
		manifests = append(manifests, value)
	}
	return manifests, rows.Err()
}

func (s *Store) ManifestRevision(ctx context.Context, deviceID string, revision int64) (Manifest, error) {
	if !deviceIDPattern.MatchString(deviceID) || revision < 1 {
		return Manifest{}, sql.ErrNoRows
	}
	var value Manifest
	var updatedAt int64
	err := s.db.QueryRowContext(ctx, `
		SELECT device_id, revision, object_hash, updated_at, references_complete
		FROM manifest_history WHERE device_id = ? AND revision = ?`, deviceID, revision,
	).Scan(&value.DeviceID, &value.Revision, &value.ObjectHash, &updatedAt, &value.ReferencesComplete)
	value.UpdatedAt = time.UnixMilli(updatedAt).UTC()
	return value, err
}

func (s *Store) PutManifestReferences(ctx context.Context, deviceID string, revision int64, hashes []string) error {
	if !deviceIDPattern.MatchString(deviceID) || revision < 1 {
		return errors.New("invalid manifest")
	}
	unique := make(map[string]struct{}, len(hashes))
	for _, hash := range hashes {
		if !objectHashPattern.MatchString(hash) {
			return errors.New("invalid object reference")
		}
		unique[hash] = struct{}{}
	}
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM manifest_history WHERE device_id = ? AND revision = ?`, deviceID, revision,
	).Scan(&exists); err != nil || exists != 1 {
		return errors.New("manifest revision not found")
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM manifest_objects WHERE device_id = ? AND revision = ?`, deviceID, revision,
	); err != nil {
		return err
	}
	for hash := range unique {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO manifest_objects(device_id, revision, object_hash) VALUES(?, ?, ?)`,
			deviceID, revision, hash,
		); err != nil {
			return fmt.Errorf("store manifest reference: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE manifest_history SET references_complete = 1 WHERE device_id = ? AND revision = ?`,
		deviceID, revision,
	); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) StorageStats(ctx context.Context) (StorageStats, error) {
	var stats StorageStats
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(size), 0) FROM objects`,
	).Scan(&stats.ObjectCount, &stats.ObjectBytes); err != nil {
		return stats, err
	}
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*),
			COALESCE(SUM(CASE WHEN references_complete = 1 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN references_complete = 0 THEN 1 ELSE 0 END), 0)
		FROM manifest_history`,
	).Scan(
		&stats.ManifestHistoryCount, &stats.CompleteManifestCount, &stats.IncompleteManifestCount,
	); err != nil {
		return stats, err
	}
	return stats, nil
}

func (s *Store) CollectGarbage(
	ctx context.Context,
	keepManifestsPerDevice int,
	minimumObjectAge time.Duration,
) (GarbageCollectionResult, error) {
	if keepManifestsPerDevice < 2 || keepManifestsPerDevice > 365 {
		return GarbageCollectionResult{}, errors.New("keepManifestsPerDevice must be between 2 and 365")
	}
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	var result GarbageCollectionResult
	devices, err := s.db.QueryContext(ctx, `SELECT DISTINCT device_id FROM manifest_history`)
	if err != nil {
		return result, err
	}
	var deviceIDs []string
	for devices.Next() {
		var deviceID string
		if err := devices.Scan(&deviceID); err != nil {
			devices.Close()
			return result, err
		}
		deviceIDs = append(deviceIDs, deviceID)
	}
	devices.Close()
	for _, deviceID := range deviceIDs {
		deleteResult, err := s.db.ExecContext(ctx, `
			DELETE FROM manifest_history
			WHERE device_id = ? AND revision NOT IN (
				SELECT revision FROM manifest_history WHERE device_id = ?
				ORDER BY revision DESC LIMIT ?
			) AND revision != COALESCE((SELECT revision FROM manifests WHERE device_id = ?), -1)`,
			deviceID, deviceID, keepManifestsPerDevice, deviceID,
		)
		if err != nil {
			return result, err
		}
		count, _ := deleteResult.RowsAffected()
		result.PrunedManifestCount += count
	}
	var incompleteCutoff int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(updated_at), 0) FROM manifest_history WHERE references_complete = 0`,
	).Scan(&incompleteCutoff); err != nil {
		return result, err
	}
	minimumCreatedAt := time.Now().Add(-minimumObjectAge).UnixMilli()
	rows, err := s.db.QueryContext(ctx, `
		SELECT object.hash, object.size FROM objects AS object
		WHERE object.created_at <= ?
		  AND (? = 0 OR object.created_at > ?)
		  AND object.hash NOT IN (SELECT object_hash FROM manifests)
		  AND object.hash NOT IN (SELECT object_hash FROM manifest_history)
		  AND object.hash NOT IN (SELECT object_hash FROM manifest_objects)`,
		minimumCreatedAt, incompleteCutoff, incompleteCutoff,
	)
	if err != nil {
		return result, err
	}
	type candidate struct {
		hash string
		size int64
	}
	var candidates []candidate
	for rows.Next() {
		var value candidate
		if err := rows.Scan(&value.hash, &value.size); err != nil {
			rows.Close()
			return result, err
		}
		candidates = append(candidates, value)
	}
	rows.Close()
	for _, value := range candidates {
		if err := os.Remove(s.objectPath(value.hash)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return result, err
		}
		deleted, err := s.db.ExecContext(ctx, `DELETE FROM objects WHERE hash = ?`, value.hash)
		if err != nil {
			return result, err
		}
		if count, _ := deleted.RowsAffected(); count > 0 {
			result.DeletedObjectCount++
			result.ReclaimedBytes += value.size
		}
	}
	result.Storage, err = s.StorageStats(ctx)
	return result, err
}

func (s *Store) objectPath(hash string) string {
	return filepath.Join(s.objectsDir, hash[:2], hash)
}
