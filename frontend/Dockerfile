# Multi-Arch Dockerfile für Podman
ARG BUILDPLATFORM
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

# Build-Argumente für Cross-Compilation  
ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG VERSION
ARG STAGE

ENV VERSION=${VERSION}
ENV APP_STAGE=${STAGE}

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
    -o asset-management-frontend .

# Runtime Stage
FROM alpine:latest

ARG VERSION
ARG STAGE

ENV VERSION=${VERSION}
ENV APP_STAGE=${STAGE}

# Security: Non-root User erstellen
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# CA certificates für HTTPS  
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Binary kopieren
COPY --from=builder /app/asset-management-frontend .

COPY templates ./templates
COPY static ./static 

# RUN echo "Templates vorhanden:" && ls -al templates

# Ownership ändern
RUN chown -R appuser:appgroup /app

EXPOSE 3000
USER appuser

CMD ["./asset-management-frontend"]