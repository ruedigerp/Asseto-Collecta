# Multi-Arch Dockerfile für Podman
ARG BUILDPLATFORM
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

# Build-Argumente für Cross-Compilation  
ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG VERSION

ENV VERSION=${VERSION}

WORKDIR /app

# Dependencies kopieren und downloaden
COPY go.mod go.sum ./
RUN go mod download
# RUN go mod tidy

# Source code kopieren
COPY . .

# Cross-compile für Target-Architektur
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -a -installsuffix cgo \
    -ldflags "-extldflags '-static' -X main.version=${VERSION}" \
    -o asset-management-api .

# Runtime Stage
FROM alpine:latest

ARG VERSION

ENV VERSION=${VERSION}

# Security: Non-root User erstellen
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# CA certificates für HTTPS  
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Binary kopieren
COPY --from=builder /app/asset-management-api .

# Ownership ändern
RUN chown -R appuser:appgroup /app

EXPOSE 8090
USER appuser

CMD ["./asset-management-api"]