package payloads

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestDecodeRoundTrip(t *testing.T) {
	if !Available() {
		t.Skip("public placeholder bundle — audit build (this repo) has no payloads by design")
	}
	srcs, err := Decode()
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	want := []string{
		"pwnkit.c", "pwnkit_main.c", "hax.c", "libnss_evil.c",
		"copyfail.c", "dirty_frag.c", "fragnesia.c", "dirty_clone.c",
		"pedit_cow.c", "cgroup_uaf.c", "ptrace_cred.c", "cve-2026-41651.c",
	}
	if len(srcs) != len(want) {
		t.Fatalf("got %d files, want %d: %v", len(srcs), len(want), keysOf(srcs))
	}
	for _, w := range want {
		data, ok := srcs[w]
		if !ok {
			t.Fatalf("bundle missing %s", w)
		}
		if len(data) < 100 {
			t.Errorf("%s suspiciously small (%d bytes)", w, len(data))
		}
		head := string(data[:min(200, len(data))])
		if !strings.Contains(head, "#") && !strings.Contains(head, "/") {
			t.Errorf("%s does not look like C source: %q", w, head[:40])
		}
	}
}

func TestBlobIsNotPlaintext(t *testing.T) {
	b, err := blobBytes()
	if err != nil {
		t.Fatalf("blobBytes: %v", err)
	}
	s := string(b)
	for _, marker := range []string{"#include", "gconv_init", "setresuid", "int main"} {
		if strings.Contains(s, marker) {
			t.Errorf("bundle contains plaintext marker %q — encryption broken?", marker)
		}
	}
}

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

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
