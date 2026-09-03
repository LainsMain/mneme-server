package auth

import "testing"

func TestGenerateParseAndMatch(t *testing.T) {
	plain, generated, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(plain)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ID != generated.ID || string(parsed.Secret) != string(generated.Secret) {
		t.Fatal("parsed token did not match generated token")
	}
	salt, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	hash := Hash(parsed.Secret, salt)
	if !Matches(parsed.Secret, salt, hash) {
		t.Fatal("valid token did not match")
	}
	parsed.Secret[0] ^= 0xff
	if Matches(parsed.Secret, salt, hash) {
		t.Fatal("modified token matched")
	}
}

func TestParseRejectsMalformedToken(t *testing.T) {
	for _, value := range []string{"", "hello", "mnm.nope", "bad.id.secret", "mnm.id.not-base64!"} {
		if _, err := Parse(value); err == nil {
			t.Fatalf("Parse(%q) unexpectedly succeeded", value)
		}
	}
}
