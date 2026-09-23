package pyrunner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/cleissonamanacio/iamroot/pylib"
)

var (
	cachedWorkdir string
	cachedOk      bool
)

func Ensure(workdir string) (string, error) {
	if cachedOk {
		return cachedWorkdir, nil
	}
	dst := filepath.Join(workdir, "pylib")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return "", err
	}
	entries, err := pylib.Assets.ReadDir(".")
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := pylib.Assets.ReadFile(e.Name())
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), data, 0o755); err != nil {
			return "", err
		}
	}
	cachedWorkdir = dst
	cachedOk = true
	return dst, nil
}

func pythonBin() string {
	for _, py := range []string{"python3", "python"} {
		if p, err := exec.LookPath(py); err == nil {
			return p
		}
	}
	return ""
}

func Run(workdir, script string, args ...string) (string, bool) {
	py := pythonBin()
	if py == "" {
		return "[-] python3 not found\n", false
	}
	if _, err := Ensure(workdir); err != nil {
		return fmt.Sprintf("[-] pyrunner extract: %v\n", err), false
	}
	path := filepath.Join(workdir, "pylib", script)
	if _, err := os.Stat(path); err != nil {
		return fmt.Sprintf("[-] pyrunner: %s not found\n", script), false
	}
	argv := append([]string{path}, args...)
	out, err := exec.Command(py, argv...).CombinedOutput()
	return string(out), err == nil
}

func SelfTest(workdir string) error {
	py := pythonBin()
	if py == "" {
		return fmt.Errorf("python3 not found")
	}
	dir, err := Ensure(workdir)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".py" {
			continue
		}
		path := filepath.Join(dir, e.Name())
		out, err := exec.Command(py, path, "--selftest").CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s selftest failed: %v\n%s", e.Name(), err, out)
		}
	}
	return nil
}
