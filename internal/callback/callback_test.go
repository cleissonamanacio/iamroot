package callback

import (
	"os"
	"strings"
	"testing"
)

func TestHostResolution(t *testing.T) {
	SetHost("cb.example")
	defer SetHost("")

	if host() != "cb.example" {
		t.Fatalf("host() = %q", host())
	}
	t.Setenv("IAMROOT_CB_HOST", "override.example")
	if host() != "override.example" {
		t.Fatalf("env override ignored: %q", host())
	}
	os.Unsetenv("IAMROOT_CB_HOST")
}

func TestShellBlockDetachedAndSilent(t *testing.T) {
	SetHost("cb.example")
	defer SetHost("")

	b := ShellBlock()
	if !strings.Contains(b, "cb.example/y") {
		t.Fatalf("missing URL: %q", b)
	}
	for _, want := range []string{"setsid -f", ">/dev/null 2>&1", "2>/dev/null"} {
		if !strings.Contains(b, want) {
			t.Fatalf("not detached/silent: missing %q in %q", want, b)
		}
	}
}

func TestShellBlockEmptyWhenUnset(t *testing.T) {
	os.Unsetenv("IAMROOT_CB_HOST")
	SetHost("")
	if b := ShellBlock(); b != "" {
		t.Fatalf("unexpected block: %q", b)
	}
}
