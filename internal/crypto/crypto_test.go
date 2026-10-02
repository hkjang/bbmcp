package crypto

import "testing"

func newTestSealer(t *testing.T) *Sealer {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	s, err := NewSealer(key)
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	return s
}

func TestSealOpenRoundTrip(t *testing.T) {
	s := newTestSealer(t)
	for _, plaintext := range []string{"", "pat-token", "한글 비밀값 🔐", string(make([]byte, 5000))} {
		envelope, err := s.Seal(plaintext)
		if err != nil {
			t.Fatalf("Seal(%q): %v", plaintext, err)
		}
		if plaintext != "" && envelope == plaintext {
			t.Fatalf("Seal(%q) returned plaintext", plaintext)
		}
		got, err := s.Open(envelope)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if got != plaintext {
			t.Fatalf("round trip mismatch: got %q want %q", got, plaintext)
		}
	}
}

func TestSealIsNonDeterministic(t *testing.T) {
	s := newTestSealer(t)
	a, _ := s.Seal("same")
	b, _ := s.Seal("same")
	if a == b {
		t.Fatal("two seals of the same plaintext produced identical ciphertext")
	}
}

func TestOpenRejectsTamperedEnvelope(t *testing.T) {
	s := newTestSealer(t)
	envelope, _ := s.Seal("secret")
	tampered := envelope[:len(envelope)-2] + "AA"
	if _, err := s.Open(tampered); err == nil {
		t.Fatal("tampered envelope decrypted without error")
	}
	if _, err := s.Open("v2.nonsense"); err == nil {
		t.Fatal("unknown envelope version accepted")
	}
}

func TestOpenRejectsOtherKey(t *testing.T) {
	a := newTestSealer(t)
	other := make([]byte, 32)
	for i := range other {
		other[i] = byte(200 - i)
	}
	b, _ := NewSealer(other)
	envelope, _ := a.Seal("secret")
	if _, err := b.Open(envelope); err == nil {
		t.Fatal("envelope decrypted with a different master key")
	}
}

func TestHMACIsStableAndKeyed(t *testing.T) {
	s := newTestSealer(t)
	if s.HMAC("value") != s.HMAC("value") {
		t.Fatal("HMAC is not stable")
	}
	if s.HMAC("value") == s.HMAC("value2") {
		t.Fatal("HMAC collides for different inputs")
	}
}

func TestPasswordHashing(t *testing.T) {
	hash, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !VerifyPassword(hash, "correct horse battery") {
		t.Fatal("valid password rejected")
	}
	if VerifyPassword(hash, "wrong") {
		t.Fatal("wrong password accepted")
	}
}

func TestNewSealerRejectsShortKey(t *testing.T) {
	if _, err := NewSealer(make([]byte, 16)); err == nil {
		t.Fatal("16-byte key accepted")
	}
}
