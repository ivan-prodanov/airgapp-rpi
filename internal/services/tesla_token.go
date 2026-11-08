// tesla_token.go — bearer-token management for /api/ble/*.
//
// V4.4 Phase 1. The byte-forwarder API is reachable over Tailscale
// Funnel (eventually) and so cannot rely on session cookies. Each
// enrolled client device gets a single high-entropy bearer; the
// plaintext is shown exactly once at issue time and stored only as a
// SHA-256 hash. Audit columns (created_at, last_used_at, revoked_at)
// let an operator triage a leak without losing history.
package services

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// teslaTokenBytes is the size of the underlying random seed for a
// bearer. 32 bytes = 256 bits of entropy; base64-url encodes to 43
// characters. Brute-forcing this online against a rate-limited public
// endpoint is computationally infeasible.
const teslaTokenBytes = 32

// TeslaClientToken is the public-facing description of a single bearer.
// The raw token text is NEVER stored in this struct after issuance — it
// only exists in the issue response.
type TeslaClientToken struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	// Plain is the re-viewable bearer, populated by List so the operator can
	// re-display a user's enrolment QR without re-issuing (v25). List returns
	// active tokens only, so this is always set there; never set on Validate/get.
	Plain string `json:"plain,omitempty"`
	// ExpiresAt is the claim window for a self-service airgapp.me token: non-NULL
	// means "must be scanned+used before this instant, else dead" (v26). Cleared
	// to NULL on first successful Validate so a claimed token is permanent.
	// Operator-issued tokens have it NULL. Only populated by Validate's scan.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// TeslaTokenIssue is what IssueToken returns. Plaintext is shown to the
// operator once and not persisted.
type TeslaTokenIssue struct {
	Token TeslaClientToken `json:"token"`
	Plain string           `json:"plain"`
}

// TeslaTokenService is the CRUD + validation surface. Held by
// services.Services; the BLE bearer middleware uses Validate, the
// admin handlers use the rest.
type TeslaTokenService struct {
	db *sql.DB
}

// NewTeslaTokenService wires the service.
func NewTeslaTokenService(db *sql.DB) *TeslaTokenService {
	return &TeslaTokenService{db: db}
}

// Issue creates a new bearer with the given operator-supplied label.
// Returns the row metadata plus the plaintext token. Caller is
// responsible for delivering plain to the operator over a confidential
// channel (the issuing session itself, ideally — never logged, never
// echoed back to the API).
//
// The label is trimmed, length-bounded, and required. Two tokens may
// share a label — there's no UNIQUE constraint on name.
func (s *TeslaTokenService) Issue(name string) (*TeslaTokenIssue, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("token name cannot be empty")
	}
	if len(name) > 80 {
		return nil, errors.New("token name too long (max 80 chars)")
	}

	seed := make([]byte, teslaTokenBytes)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("seed bearer: %w", err)
	}
	plain := base64.RawURLEncoding.EncodeToString(seed)
	hash := hashTeslaToken(plain)

	res, err := s.db.Exec(
		"INSERT INTO tesla_client_tokens (name, token_hash, token_plain) VALUES (?, ?, ?)",
		name, hash, plain,
	)
	if err != nil {
		return nil, fmt.Errorf("insert token: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("token id: %w", err)
	}

	row, err := s.get(id)
	if err != nil {
		return nil, err
	}
	return &TeslaTokenIssue{Token: *row, Plain: plain}, nil
}

// IssueEphemeral mints a bearer with a claim window: it works only if scanned
// and first-used within ttl, after which Validate clears the window and the
// token becomes permanent (see Validate). Used by the self-service airgapp.me
// enrol page so an unscanned QR can't linger as a live credential. Same shape
// as Issue otherwise — the plaintext is returned once.
//
// expires_at is computed in UTC and stored in SQLite's datetime text format so
// it compares directly against CURRENT_TIMESTAMP (also UTC) without timezone
// ambiguity in the Validate fast-path.
func (s *TeslaTokenService) IssueEphemeral(name string, ttl time.Duration) (*TeslaTokenIssue, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("token name cannot be empty")
	}
	if len(name) > 80 {
		return nil, errors.New("token name too long (max 80 chars)")
	}
	if ttl <= 0 {
		return nil, errors.New("ttl must be positive")
	}

	seed := make([]byte, teslaTokenBytes)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("seed bearer: %w", err)
	}
	plain := base64.RawURLEncoding.EncodeToString(seed)
	hash := hashTeslaToken(plain)
	expiresAt := time.Now().UTC().Add(ttl).Format("2006-01-02 15:04:05")

	// Prune lapsed, never-claimed codes so repeated self-service issuance can't
	// grow the table without bound. Claimed tokens have expires_at cleared to
	// NULL, so this only ever removes dead unscanned QRs.
	_, _ = s.db.Exec("DELETE FROM tesla_client_tokens WHERE expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP")

	res, err := s.db.Exec(
		"INSERT INTO tesla_client_tokens (name, token_hash, token_plain, expires_at) VALUES (?, ?, ?, ?)",
		name, hash, plain, expiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("insert ephemeral token: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("token id: %w", err)
	}

	row, err := s.get(id)
	if err != nil {
		return nil, err
	}
	return &TeslaTokenIssue{Token: *row, Plain: plain}, nil
}

// List returns the active tokens, newest first, each with its re-viewable
// plaintext. The operator UI renders them as the "Users" table; a removed
// (hard-deleted) or self-revoked token never appears.
func (s *TeslaTokenService) List() ([]TeslaClientToken, error) {
	// Active tokens only — "Remove" hard-deletes, and a self-revoked token is
	// dead, so the admin UI shows a flat list of live users (no status column).
	rows, err := s.db.Query(`
		SELECT id, name, created_at, last_used_at, revoked_at, token_plain
		FROM tesla_client_tokens
		WHERE revoked_at IS NULL
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list tokens: %w", err)
	}
	defer rows.Close()

	var out []TeslaClientToken
	for rows.Next() {
		var t TeslaClientToken
		if err := rows.Scan(&t.ID, &t.Name, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt, &t.Plain); err != nil {
			return nil, fmt.Errorf("scan token: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Revoke flips revoked_at to now() for the given token id. Idempotent —
// revoking an already-revoked token is a no-op (revoked_at stays at
// its original timestamp). Returns ErrTokenNotFound if no such id.
func (s *TeslaTokenService) Revoke(id int64) error {
	res, err := s.db.Exec(
		"UPDATE tesla_client_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE id = ? AND revoked_at IS NULL",
		id,
	)
	if err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		// Could be "doesn't exist" or "already revoked" — distinguish.
		var exists int
		_ = s.db.QueryRow("SELECT COUNT(*) FROM tesla_client_tokens WHERE id = ?", id).Scan(&exists)
		if exists == 0 {
			return ErrTeslaTokenNotFound
		}
	}
	return nil
}

// Delete permanently removes a token row — the admin "Remove" action. This is
// a HARD delete (not the soft Revoke): the row is gone from the list and the
// client loses access immediately. Returns ErrTeslaTokenNotFound if no such id.
func (s *TeslaTokenService) Delete(id int64) error {
	res, err := s.db.Exec("DELETE FROM tesla_client_tokens WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrTeslaTokenNotFound
	}
	return nil
}

// Validate looks up a plaintext bearer by its hash. Returns the token
// row on success (active, not revoked) and bumps last_used_at. The
// returned name is what the bearer middleware stuffs into request
// context for audit-log attribution.
//
// Returns ErrTeslaTokenInvalid if no match OR the token is revoked.
// Distinguishing those two cases would leak which tokens exist, so we
// don't.
func (s *TeslaTokenService) Validate(plain string) (*TeslaClientToken, error) {
	plain = strings.TrimSpace(plain)
	if plain == "" {
		return nil, ErrTeslaTokenInvalid
	}
	hash := hashTeslaToken(plain)

	var t TeslaClientToken
	// The expires_at clause enforces the claim window in the DB's own clock
	// (CURRENT_TIMESTAMP, UTC) so there's no Go-side timezone comparison on the
	// auth fast-path. An expired row simply doesn't match — indistinguishable
	// from "not found"/"revoked", which is the point (no existence oracle).
	err := s.db.QueryRow(`
		SELECT id, name, created_at, last_used_at, revoked_at, expires_at
		FROM tesla_client_tokens
		WHERE token_hash = ? AND revoked_at IS NULL
		  AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`,
		hash,
	).Scan(&t.ID, &t.Name, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt, &t.ExpiresAt)
	if err == sql.ErrNoRows {
		return nil, ErrTeslaTokenInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("validate token: %w", err)
	}

	// Claim-on-first-use: a self-service airgapp.me token proves itself by being
	// used inside its window (it passed the clause above). Clear the window so
	// it is permanent from here on — only ever runs once per token, and an
	// unclaimed one would already have failed the WHERE and never reach here.
	if t.ExpiresAt != nil {
		_, _ = s.db.Exec("UPDATE tesla_client_tokens SET expires_at = NULL WHERE id = ?", t.ID)
		t.ExpiresAt = nil
	}

	// Best-effort touch — failure here doesn't deny access (the bearer
	// was still valid this instant), it just means the next "last used"
	// timestamp is slightly stale. The op-ux value of this column
	// (telling an operator which tokens are idle and safe to revoke) is
	// not worth coupling the auth fast-path to write availability.
	_, _ = s.db.Exec(
		"UPDATE tesla_client_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?",
		t.ID,
	)

	return &t, nil
}

func (s *TeslaTokenService) get(id int64) (*TeslaClientToken, error) {
	var t TeslaClientToken
	err := s.db.QueryRow(`
		SELECT id, name, created_at, last_used_at, revoked_at
		FROM tesla_client_tokens WHERE id = ?`,
		id,
	).Scan(&t.ID, &t.Name, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt)
	if err != nil {
		return nil, fmt.Errorf("get token: %w", err)
	}
	return &t, nil
}

// hashTeslaToken is the one-way function used to derive token_hash. We
// use plain SHA-256 (not bcrypt/argon) because the input is already a
// uniformly-random 256-bit secret — a slow KDF would buy nothing
// against an offline guess attempt, but would cost real latency on
// every API call. Hash is hex-encoded so the DB column stays
// human-readable.
func hashTeslaToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// Sentinel errors so handlers can map to HTTP codes precisely.
var (
	ErrTeslaTokenNotFound = errors.New("tesla client token not found")
	ErrTeslaTokenInvalid  = errors.New("tesla client token invalid or revoked")
)
