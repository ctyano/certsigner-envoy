# note: never use the :latest tag in a production site
FROM docker.io/library/golang:1 AS builder

ARG APP_NAME=certsigner-envoy
ARG VERSION=test

ENV APP_NAME=${APP_NAME}

WORKDIR ${GOPATH}/src/${APP_NAME}

RUN apt-get update && apt-get install -y curl cmake g++ make unzip curl git tzdata tree bash

COPY . .

RUN go mod tidy
RUN GOOS=wasip1 \
    GOARCH=wasm \
    go build -buildmode=c-shared -o "${APP_NAME}.wasm" \
    && mv ${GOPATH}/src/${APP_NAME}/"${APP_NAME}.wasm" /opt/"${APP_NAME}.wasm"

RUN rm -rf "${GOPATH}"

# [Required] A host environment supporting this toolchain, such as Envoy >= 1.33.0. This SDK leverages additional host imports added to the proxy-wasm-cpp-host in PR#427.
# https://github.com/proxy-wasm/proxy-wasm-go-sdk/blob/ab4161dcf9246a828008b539a82a1556cf0f2e24/README.md#requirements
# https://github.com/proxy-wasm/proxy-wasm-cpp-host/pull/427
FROM docker.io/envoyproxy/envoy:v1.34-latest

RUN apt-get update && \
    apt-get install -y curl openssl wabt

ARG APP_NAME=certsigner-envoy

COPY --from=builder /opt/"${APP_NAME}.wasm" /etc/envoy/${APP_NAME}.wasm

