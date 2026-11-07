package services

import (
	"errors"
	"strings"
	"testing"
)

func TestTeslaToken_IssueReturnsHighEntropyPlaintext(t *testing.T) {
	db := memDB(t)
	s := NewTeslaTokenService(db)

	issued, err := s.Issue("ivan's macbook")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// 32 random bytes → 43-char base64url with no padding.
	if got, want := len(issued.Plain), 43; got != want {
		t.Errorf("token length = %d, want %d (%q)", got, want, issued.Plain)
	}
	if strings.ContainsAny(issued.Plain, "=+/") {
		t.Errorf("token contains non-URL-safe chars: %q", issued.Plain)
	}
	if issued.Token.ID == 0 {
		t.Errorf("token id should be assigned")
	}
	if issued.Token.Name != "ivan's macbook" {
		t.Errorf("name = %q, want 'ivan's macbook'", issued.Token.Name)
	}
}

func TestTeslaToken_PlaintextNeverPersisted(t *testing.T) {
	db := memDB(t)
	s := NewTeslaTokenService(db)

	issued, err := s.Issue("test")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// The plaintext must not appear anywhere in the row — only its hash.
	var hash string
	if err := db.QueryRow("SELECT token_hash FROM tesla_client_tokens WHERE id = ?", issued.Token.ID).Scan(&hash); err != nil {
		t.Fatalf("read hash: %v", err)
	}
	if hash == issued.Plain {
		t.Errorf("DB stores plaintext, not a hash")
	}
	if hash != hashTeslaToken(issued.Plain) {
		t.Errorf("DB hash != sha256(plain)")
	}
}

func TestTeslaToken_ValidateRoundTrips(t *testing.T) {
	db := memDB(t)
	s := NewTeslaTokenService(db)

	issued, err := s.Issue("client")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	tok, err := s.Validate(issued.Plain)
	if err != nil {
		t.Fatalf("validate good token: %v", err)
	}
	if tok.ID != issued.Token.ID {
		t.Errorf("validate id = %d, want %d", tok.ID, issued.Token.ID)
	}
	if tok.Name != "client" {
		t.Errorf("validate name = %q", tok.Name)
	}
}

func TestTeslaToken_ValidateRejectsUnknown(t *testing.T) {
	db := memDB(t)
	s := NewTeslaTokenService(db)

	_, err := s.Validate("definitely-not-a-real-token-1234567890")
	if !errors.Is(err, ErrTeslaTokenInvalid) {
		t.Errorf("unknown token err = %v, want ErrTeslaTokenInvalid", err)
	}
}

func TestTeslaToken_ValidateRejectsRevoked(t *testing.T) {
	db := memDB(t)
	s := NewTeslaTokenService(db)

	issued, err := s.Issue("doomed")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := s.Revoke(issued.Token.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_, err = s.Validate(issued.Plain)
	if !errors.Is(err, ErrTeslaTokenInvalid) {
		t.Errorf("revoked token err = %v, want ErrTeslaTokenInvalid", err)
	}
}

func TestTeslaToken_IssueRejectsEmptyName(t *testing.T) {
	db := memDB(t)
	s := NewTeslaTokenService(db)

	if _, err := s.Issue(""); err == nil {
		t.Errorf("empty name should fail")
	}
	if _, err := s.Issue("   "); err == nil {
		t.Errorf("whitespace-only name should fail")
	}
}

func TestTeslaToken_RevokeUnknownReturnsNotFound(t *testing.T) {
	db := memDB(t)
	s := NewTeslaTokenService(db)

	err := s.Revoke(999)
	if !errors.Is(err, ErrTeslaTokenNotFound) {
		t.Errorf("revoke 999 err = %v, want ErrTeslaTokenNotFound", err)
	}
}

func TestTeslaToken_RevokeIsIdempotent(t *testing.T) {
	db := memDB(t)
	s := NewTeslaTokenService(db)

	issued, err := s.Issue("twice-revoked")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := s.Revoke(issued.Token.ID); err != nil {
		t.Fatalf("revoke 1: %v", err)
	}
	// Second revoke is a no-op, not an error.
	if err := s.Revoke(issued.Token.ID); err != nil {
		t.Errorf("revoke 2: %v (should be no-op)", err)
	}
}

func TestTeslaToken_ListShowsOnlyActive(t *testing.T) {
	db := memDB(t)
	s := NewTeslaTokenService(db)

	if _, err := s.Issue("alpha"); err != nil {
		t.Fatal(err)
	}
	bravo, err := s.Issue("bravo")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(bravo.Token.ID); err != nil {
		t.Fatal(err)
	}

	rows, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	// The admin UI shows live users only — a revoked (self-destructed) token is
	// gone from the list, so "if it's there, it's active".
	if len(rows) != 1 {
		t.Fatalf("list len = %d, want 1 (active only)", len(rows))
	}
	if rows[0].Name != "alpha" || rows[0].RevokedAt != nil {
		t.Errorf("row 0 = %+v, want active alpha", rows[0])
	}
}

func TestTeslaToken_DeleteRemovesRow(t *testing.T) {
	db := memDB(t)
	s := NewTeslaTokenService(db)

	issued, err := s.Issue("to-delete")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := s.Delete(issued.Token.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Hard delete — the row is gone from the table entirely (not just revoked).
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM tesla_client_tokens WHERE id = ?", issued.Token.ID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("row count after delete = %d, want 0", n)
	}
	// And the bearer stops validating.
	if _, err := s.Validate(issued.Plain); !errors.Is(err, ErrTeslaTokenInvalid) {
		t.Errorf("validate deleted token err = %v, want ErrTeslaTokenInvalid", err)
	}
}

func TestTeslaToken_DeleteUnknownReturnsNotFound(t *testing.T) {
	db := memDB(t)
	s := NewTeslaTokenService(db)

	if err := s.Delete(999); !errors.Is(err, ErrTeslaTokenNotFound) {
		t.Errorf("delete 999 err = %v, want ErrTeslaTokenNotFound", err)
	}
}

func TestTeslaToken_IssuedTokensAreUnique(t *testing.T) {
	// Sanity: two consecutive issues with the same name yield distinct
	// plaintexts (otherwise the seed RNG is broken).
	db := memDB(t)
	s := NewTeslaTokenService(db)

	a, _ := s.Issue("same-name")
	b, _ := s.Issue("same-name")
	if a.Plain == b.Plain {
		t.Errorf("two issues produced the same plaintext — RNG fail")
	}
}

// TestTeslaToken_ListExposesPlaintextForReview verifies v25's re-viewable QR:
// List returns the stored plaintext for ACTIVE tokens so the operator can
// re-show a user's enrolment QR. Revoked tokens drop out of the list entirely.
func TestTeslaToken_ListExposesPlaintextForReview(t *testing.T) {
	db := memDB(t)
	s := NewTeslaTokenService(db)

	a, err := s.Issue("phone-a")
	if err != nil {
		t.Fatalf("issue a: %v", err)
	}
	b, err := s.Issue("phone-b")
	if err != nil {
		t.Fatalf("issue b: %v", err)
	}
	if err := s.Revoke(b.Token.ID); err != nil {
		t.Fatalf("revoke b: %v", err)
	}

	list, err := s.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	byName := map[string]TeslaClientToken{}
	for _, tok := range list {
		byName[tok.Name] = tok
	}

	// Active token: plaintext is returned and matches what Issue handed back,
	// so rebuilding the QR yields the same enrolment URL.
	if got := byName["phone-a"].Plain; got != a.Plain {
		t.Errorf("active token Plain = %q, want the issued plaintext %q", got, a.Plain)
	}
	// Revoked token: absent from the list, so its plaintext never ships.
	if _, present := byName["phone-b"]; present {
		t.Errorf("revoked token appeared in List — want active-only")
	}
}
