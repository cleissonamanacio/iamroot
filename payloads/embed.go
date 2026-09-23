package payloads

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
)

//go:embed bin/*.enc
var files embed.FS

const key = "iamroot.v1"

func blobBytes() ([]byte, error) {
	if b, err := files.ReadFile("bin/payloads.enc"); err == nil && len(b) > 0 {
		return b, nil
	}
	if b, err := files.ReadFile("bin/payloads.public.enc"); err == nil {
		return b, nil
	}
	return nil, fmt.Errorf("no payload bundle embedded")
}

func Available() bool {
	_, err := Decode()
	return err == nil
}

func keystream(n int) []byte {
	out := make([]byte, 0, n+sha256.Size)
	for c := uint32(0); len(out) < n; c++ {
		h := sha256.New()
		h.Write([]byte(key))
		var ctr [4]byte
		binary.LittleEndian.PutUint32(ctr[:], c)
		h.Write(ctr[:])
		out = h.Sum(out)
	}
	return out[:n]
}

func Decode() (map[string][]byte, error) {
	b, err := blobBytes()
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("payload bundle is empty")
	}
	ks := keystream(len(raw))
	buf := make([]byte, len(raw))
	for i := range raw {
		buf[i] = raw[i] ^ ks[i]
	}

	out := map[string][]byte{}
	for len(buf) > 0 {
		if len(buf) < 2 {
			return nil, fmt.Errorf("corrupt bundle: truncated name length")
		}
		nl := int(binary.LittleEndian.Uint16(buf))
		buf = buf[2:]
		if nl == 0 || nl > 256 || len(buf) < nl {
			return nil, fmt.Errorf("corrupt bundle: bad name")
		}
		name := string(buf[:nl])
		buf = buf[nl:]
		if len(buf) < 8 {
			return nil, fmt.Errorf("corrupt bundle: truncated size for %s", name)
		}
		dl := int(binary.LittleEndian.Uint64(buf))
		buf = buf[8:]
		if dl < 0 || len(buf) < dl {
			return nil, fmt.Errorf("corrupt bundle: bad data for %s", name)
		}
		out[name] = buf[:dl]
		buf = buf[dl:]
	}
	return out, nil
}
