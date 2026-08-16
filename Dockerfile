# eksuvia needs to talk to the host's container runtime to create kind
# clusters, so this image expects /var/run/docker.sock to be mounted. See
# docker-compose.yml.
FROM golang:1.24-alpine AS build

WORKDIR /src

# Copy manifests first so dependency resolution is cached independently of
# source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 go build \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/eksuvia ./cmd/eksuvia

FROM alpine:3.20

# ca-certificates for outbound HTTPS (pulling node images is done by the
# container runtime, but the runtime client still validates endpoints).
RUN apk add --no-cache ca-certificates

COPY --from=build /out/eksuvia /usr/local/bin/eksuvia

# eksuvia runs as root because it needs access to the mounted container runtime
# socket. It is a local development tool and must not be exposed off-host.
EXPOSE 4566

ENTRYPOINT ["/usr/local/bin/eksuvia"]
