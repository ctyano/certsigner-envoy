# certsigner-envoy

This is an unofficial repository to provide packages for [Athenz](https://www.athenz.io).

It is currently owned and maintained by [ctyano](https://github.com/ctyano).

This certsigner-envoy provides a JWT authentication (intended with OIDC Access Token) by running as a proxy in front of [cyrpki](https://github.com/theparanoids/crypki) or [cfssl](https://github.com/cloudflare/cfssl).

This repository relies on [WebAssembly for Proxies (Go SDK)](https://github.com/proxy-wasm/proxy-wasm-go-sdk).

## How to build

```
make
```

## List of Distributions

### Docker(OCI) Image

[certsigner-envoy](https://github.com/users/ctyano/packages/container/package/certsigner-envoy)

