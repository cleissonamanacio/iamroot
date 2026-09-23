package creds

import (
	"strings"
	"sync"
)

var (
	mu  sync.Mutex
	all []string
)

func Add(p string) {
	p = strings.TrimSpace(p)
	if p == "" {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	for _, e := range all {
		if e == p {
			return
		}
	}
	all = append(all, p)
}

func AddMany(ps []string) {
	for _, p := range ps {
		Add(p)
	}
}

func Count() int { mu.Lock(); defer mu.Unlock(); return len(all) }

func GetAll() []string {
	mu.Lock()
	defer mu.Unlock()
	out := make([]string, len(all))
	copy(out, all)
	return out
}

func IsRealPassword(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 4 || len(s) > 128 {
		return false
	}
	lower := strings.ToLower(s)
	for _, junk := range []string{
		"true", "false", "null", "none", "password", "changeme", "yourpass",
		"example", "secret_key", "api_key", "replace", "xxxxx", "nopasswd",
	} {
		if lower == junk {
			return false
		}
	}

	if strings.Contains(s, "{{") || strings.HasPrefix(s, "${") {
		return false
	}

	if strings.Count(s, ".") >= 2 {
		hasNonDigit := false
		for _, r := range s {
			if (r < '0' || r > '9') && r != '.' {
				hasNonDigit = true
				break
			}
		}
		if !hasNonDigit {
			return false
		}
	}
	return true
}
