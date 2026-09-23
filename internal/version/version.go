package version

import (
	"strconv"
	"strings"
)

type Kernel struct {
	Major, Minor, Patch, Build int
	Raw                        string
}

func ParseKernel(s string) Kernel {
	k := Kernel{Raw: s}
	tokens := digitTokens(s)
	if len(tokens) > 0 {
		k.Major = tokens[0]
	}
	if len(tokens) > 1 {
		k.Minor = tokens[1]
	}
	if len(tokens) > 2 {
		k.Patch = tokens[2]
	}
	if len(tokens) > 3 {
		k.Build = tokens[3]
	}
	return k
}

func (k Kernel) compare(o Kernel) int {
	for i, pair := range [][2]int{
		{k.Major, o.Major}, {k.Minor, o.Minor},
		{k.Patch, o.Patch}, {k.Build, o.Build},
	} {
		if pair[0] < pair[1] {
			return -1
		}
		if pair[0] > pair[1] {
			return +1
		}
		_ = i
	}
	return 0
}

func (k Kernel) GE(o Kernel) bool { return k.compare(o) >= 0 }

func (k Kernel) LT(o Kernel) bool { return k.compare(o) < 0 }

func (k Kernel) InRange(lo, hi Kernel) bool { return k.GE(lo) && k.LT(hi) }

type SV struct {
	Parts []int
	Raw   string
}

func Parse(s string) SV {
	s = strings.TrimSpace(s)

	end := len(s)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && c != '.' {
			end = i
			break
		}
	}
	v := SV{Raw: s}
	for _, t := range strings.Split(s[:end], ".") {
		if t == "" {
			continue
		}
		n, err := strconv.Atoi(t)
		if err != nil {
			break
		}
		v.Parts = append(v.Parts, n)
	}
	return v
}

func (v SV) AtLeast(target []int) bool {
	for i := 0; i < len(target); i++ {
		got := 0
		if i < len(v.Parts) {
			got = v.Parts[i]
		}
		if got > target[i] {
			return true
		}
		if got < target[i] {
			return false
		}
	}
	return true
}

func (v SV) Less(target []int) bool {
	for i := 0; i < len(target); i++ {
		got := 0
		if i < len(v.Parts) {
			got = v.Parts[i]
		}
		if got < target[i] {
			return true
		}
		if got > target[i] {
			return false
		}
	}
	return false
}

func digitTokens(s string) []int {
	var out []int
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			if n, err := strconv.Atoi(cur.String()); err == nil {
				out = append(out, n)
			}
			cur.Reset()
		}
	}
	for _, r := range s {
		if r >= '0' && r <= '9' {
			cur.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return out
}
