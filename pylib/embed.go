package pylib

import "embed"

//go:embed *.py
var Assets embed.FS
