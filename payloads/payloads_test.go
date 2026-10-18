package payloads

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestPlaceholderIsNotAvailable(t *testing.T) {
	pub, err := files.ReadFile("bin/payloads.public.enc")
	if err != nil {
		t.Skip("no public placeholder present (full dev tree) — fine")
	}
	if string(pub) == "" {
		t.Fatal("public placeholder is empty — go:embed would fail on fresh clones")
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(pub)))
	if err != nil {
		t.Fatalf("placeholder is not valid base64: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("placeholder decodes to nothing — would read as a broken-but-loadable bundle")
	}
	if _, err := Decode(); err == nil && len(pub) > 0 && string(pub) != "" {

		if _, realErr := files.ReadFile("bin/payloads.enc"); realErr != nil && Available() {
			t.Fatal("placeholder bundle decoded successfully — real payload data may have been committed")
		}
	}
}
