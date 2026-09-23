FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY pylib/ pylib/
COPY payloads/ payloads/
COPY cmd/ cmd/
COPY internal/ internal/
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
        go build -trimpath -ldflags="-s -w" -o /out/iamroot-linux-amd64 ./cmd/iamroot \
        && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
        go build -trimpath -ldflags="-s -w" -o /out/iamroot-linux-arm64 ./cmd/iamroot

FROM caddy:2-alpine
COPY --from=build /out/ /srv/iamroot/
COPY scripts/install.sh /srv/iamroot/iamroot
COPY scripts/stage2.sh /srv/iamroot/stage2
COPY deploy/Caddyfile /etc/caddy/Caddyfile
RUN cd /srv/iamroot \
        && chmod 755 iamroot stage2 iamroot-linux-* \
        && sha256sum iamroot-linux-* > SHA256SUMS
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
        CMD wget -q -O /dev/null http://localhost:8080/SHA256SUMS || exit 1
