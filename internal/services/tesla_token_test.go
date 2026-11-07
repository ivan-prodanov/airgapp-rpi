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

func TestTeslaToken_ListShowsActiveAndRevoked(t *testing.T) {
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
	if len(rows) != 2 {
		t.Fatalf("list len = %d, want 2", len(rows))
	}
	// Order: active first, revoked after.
	if rows[0].Name != "alpha" || rows[0].RevokedAt != nil {
		t.Errorf("row 0 = %+v, want active alpha", rows[0])
	}
	if rows[1].Name != "bravo" || rows[1].RevokedAt == nil {
		t.Errorf("row 1 = %+v, want revoked bravo", rows[1])
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
// List returns the stored plaintext for ACTIVE tokens (so the operator can
// re-show a user's enrolment QR) but never for revoked ones.
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
	// Revoked token: plaintext must be withheld.
	if got := byName["phone-b"].Plain; got != "" {
		t.Errorf("revoked token Plain = %q, want empty (never ship a revoked token's plaintext)", got)
	}
}
