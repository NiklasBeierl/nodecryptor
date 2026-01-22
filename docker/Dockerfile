FROM golang:1.25-alpine AS builder

RUN apk add --no-cache \
    iproute2 \
    nftables \
    wireguard-tools

RUN go install github.com/go-delve/delve/cmd/dlv@latest

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY internal ./internal
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -gcflags="all=-N -l" -o nodeCryptor .

ENTRYPOINT ["/go/bin/dlv", "--listen=:40000", "--headless=true", "--api-version=2", "--accept-multiclient", "exec", "/app/nodeCryptor", "--"]
CMD []

FROM builder AS release
RUN CGO_ENABLED=0 GOOS=linux go build -o nodeCryptor .

FROM alpine:3.21

RUN apk add --no-cache \
    iproute2 \
    nftables \
    wireguard-tools

COPY --from=release /app/nodeCryptor /usr/local/bin/nodeCryptor

ENTRYPOINT ["/usr/local/bin/nodeCryptor"]
CMD []
