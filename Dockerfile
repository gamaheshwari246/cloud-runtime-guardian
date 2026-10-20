# Pin base image digests in your release pipeline before production rollout.
FROM golang:1.26-bookworm AS builder
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/crg-server ./cmd/server \
 && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/crg-collector ./cmd/collector

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/crg-server /usr/local/bin/crg-server
COPY --from=builder /out/crg-collector /usr/local/bin/crg-collector
USER 65532:65532
EXPOSE 9443
ENTRYPOINT ["/usr/local/bin/crg-server"]
CMD ["-addr", "0.0.0.0:9443", "-data", "/var/lib/crg/journal.jsonl", "-tls-cert", "/etc/crg/tls/tls.crt", "-tls-key", "/etc/crg/tls/tls.key"]
