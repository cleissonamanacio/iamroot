package version

import "testing"

func TestParseKernel(t *testing.T) {
	cases := []struct {
		in                   string
		majr, minr, pat, bld int
	}{
		{"5.15.0-91-generic", 5, 15, 0, 91},
		{"4.9.0-19-amd64", 4, 9, 0, 19},
		{"6.1.0-13", 6, 1, 0, 13},
		{"3.10.0-1160.el7.x86_64", 3, 10, 0, 1160},
		{"2.6.32", 2, 6, 32, 0},
	}
	for _, c := range cases {
		k := ParseKernel(c.in)
		if k.Major != c.majr || k.Minor != c.minr || k.Patch != c.pat || k.Build != c.bld {
			t.Errorf("ParseKernel(%q) = %d.%d.%d.%d, want %d.%d.%d.%d",
				c.in, k.Major, k.Minor, k.Patch, k.Build, c.majr, c.minr, c.pat, c.bld)
		}
	}
}

func TestKernelRange(t *testing.T) {

	dirtyPipe := []struct {
		ver  string
		want bool
	}{
		{"5.8.0", true},
		{"5.10.101", true},
		{"5.10.102-generic", false},
		{"5.15.0-91-generic", true},
		{"5.15.25", false},
		{"5.16.10", true},
		{"5.16.11", false},
		{"5.4.0-91", false},
	}
	lo1, hi1 := ParseKernel("5.8.0"), ParseKernel("5.10.102")
	lo2, hi2 := ParseKernel("5.15.0"), ParseKernel("5.15.25")
	lo3, hi3 := ParseKernel("5.16.0"), ParseKernel("5.16.11")
	for _, c := range dirtyPipe {
		k := ParseKernel(c.ver)
		got := k.InRange(lo1, hi1) || k.InRange(lo2, hi2) || k.InRange(lo3, hi3)
		if got != c.want {
			t.Errorf("DirtyPipe range(%q) = %v, want %v", c.ver, got, c.want)
		}
	}
}

func TestSV(t *testing.T) {

	if v := Parse("1.8.31"); !v.AtLeast([]int{1, 8, 2}) || !v.Less([]int{1, 9, 6}) {
		t.Error("sudo 1.8.31 should be in Baron Samedit range")
	}
	if v := Parse("1.9.5p1"); !v.Less([]int{1, 9, 5, 2}) {

		t.Error("sudo 1.9.5p1 parse mismatch")
	}
	if v := Parse("1.9.16"); !v.AtLeast([]int{1, 9, 6}) {
		t.Error("sudo 1.9.16 should be >= 1.9.6 (patched)")
	}
}

func TestCompareOrdering(t *testing.T) {
	a := ParseKernel("5.4.0-72-generic")
	b := ParseKernel("5.4.0-71-generic")
	if !a.GE(b) {
		t.Error("5.4.0-72 should be >= 5.4.0-71")
	}
	if b.LT(a) != true {
		t.Error("5.4.0-71 should be < 5.4.0-72")
	}
}
