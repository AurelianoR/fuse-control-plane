# ── Stage 1: Build ───────────────────────────────────────────────────────────
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy dependency files first for better layer caching
COPY go.mod ./
RUN go mod download 2>/dev/null || true

# Copy source and build a static binary
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o fuse-api main.go

# ── Stage 2: Minimal production image ────────────────────────────────────────
FROM alpine:3.19

WORKDIR /app

# CA certificates needed for outbound calls to Azure/AWS/GCP APIs
RUN apk --no-cache add ca-certificates tzdata

# Non-root user for security hardening
RUN addgroup -S fuse && adduser -S fuse -G fuse
USER fuse

COPY --from=builder /app/fuse-api .

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:8080/api/health || exit 1

CMD ["./fuse-api"]
