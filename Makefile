LDFLAGS := -s -w

.PHONY: build build-amd64 build-arm64 all native test vet selftest dryrun checksums stage clean fmt

build build-amd64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o dist/iamroot-linux-amd64 ./cmd/iamroot

build-arm64:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o dist/iamroot-linux-arm64 ./cmd/iamroot

all: build-amd64 build-arm64

native:
	go build -o dist/iamroot-native ./cmd/iamroot

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -s -w .

selftest:
	go run ./cmd/iamroot --selftest-py

dryrun:
	go run ./cmd/iamroot --list

checksums:
	cd dist && { command -v sha256sum >/dev/null 2>&1 && sha256sum iamroot-linux-* || shasum -a 256 iamroot-linux-*; } > SHA256SUMS

stage: all checksums
	cp scripts/install.sh dist/iamroot
	cp scripts/stage2.sh dist/stage2

CB_LD :=
ifneq ($(CB_HOST),)
CB_LD := -X main.cbHost=$(CB_HOST)
endif

private-bundle:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
		-ldflags="-s -w $(CB_LD)" -o dist/iamroot-linux-amd64 ./cmd/iamroot
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
		-ldflags="-s -w $(CB_LD)" -o dist/iamroot-linux-arm64 ./cmd/iamroot
	mkdir -p private
	cp dist/iamroot-linux-amd64 private/iamroot-full-linux-amd64
	cp dist/iamroot-linux-arm64 private/iamroot-full-linux-arm64
	cd private && { command -v sha256sum >/dev/null 2>&1 && sha256sum iamroot-full-* || shasum -a 256 iamroot-full-*; } > SHA256SUMS
	@[ -n "$(CB_HOST)" ] || echo "[!] CB_HOST empty — building without it"
	@echo "[+] private bundle in ./private — rsync to the server mirror:"
	@echo "    rsync -av private/ SERVER:/opt/iamroot/private/"

clean:
	rm -rf dist private
