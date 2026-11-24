FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build-stage

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download && \
    go mod verify

COPY . .

ARG VERSION=dev

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o ubyte-webssh-bridge ./cmd/ubyte-webssh-bridge

FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5

COPY --from=build-stage /app/ubyte-webssh-bridge /usr/local/bin/ubyte-webssh-bridge

USER 65532:65532

EXPOSE 8443

# The probe reads the configuration and dials the listen address.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/ubyte-webssh-bridge", "-health"]

ENTRYPOINT ["/usr/local/bin/ubyte-webssh-bridge"]
