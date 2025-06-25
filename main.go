package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm/types"
)

type CSRRequest struct {
	CSR string `json:"csr"`
}

func main() {}

func init() {
	// Plugin authors can use any one of four entrypoints, such as
	// `proxywasm.SetVMContext`, `proxywasm.SetPluginContext`, or
	// `proxywasm.SetTcpContext`.
	proxywasm.SetHttpContext(func(contextID uint32) types.HttpContext {
		return &httpContext{}
	})
}

type httpContext struct {
	types.DefaultHttpContext
}

func (*httpContext) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	hs, err := proxywasm.GetHttpRequestHeaders()
	if err != nil {
		proxywasm.LogCriticalf("failed to get request headers: %v", err)
	}

	for _, h := range hs {
		proxywasm.LogInfof("request header --> %s: %s", h[0], h[1])
	}
	auth, err := proxywasm.GetHttpRequestHeader("authorization")
	if err != nil || !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		proxywasm.SendHttpResponse(401, nil, []byte("Missing or invalid authorization header"), -1)
		return types.ActionPause
	}
	// JWT: not validated, just parsed for sub
	rawJWT := strings.TrimPrefix(auth, "Bearer ")
	token, _, err := new(jwt.Parser).ParseUnverified(rawJWT, jwt.MapClaims{})
	if err != nil {
		proxywasm.SendHttpResponse(401, nil, []byte("Invalid JWT"), -1)
		return types.ActionPause
	}
	claims := token.Claims.(jwt.MapClaims)
	sub, ok := claims["sub"].(string)
	if !ok {
		proxywasm.SendHttpResponse(403, nil, []byte("No sub claim"), -1)
		return types.ActionPause
	}
	// Save sub for later in context
	proxywasm.SetProperty([]string{"request_sub"}, []byte(sub))
	return types.ActionContinue
}

func (ctx *httpContext) OnHttpRequestBody(bodySize int, endOfStream bool) types.Action {
	if !endOfStream {
		return types.ActionPause
	}
	// Get sub claim from context property
	subBytes, _ := proxywasm.GetProperty([]string{"request_sub"})
	sub := string(subBytes)
	body, err := proxywasm.GetHttpRequestBody(0, bodySize)
	if err != nil {
		proxywasm.SendHttpResponse(400, nil, []byte("Failed to read body"), -1)
		return types.ActionPause
	}
	var req CSRRequest
	if err := json.Unmarshal(body, &req); err != nil || req.CSR == "" {
		proxywasm.SendHttpResponse(400, nil, []byte("Invalid JSON or missing csr"), -1)
		return types.ActionPause
	}
	block, _ := pem.Decode([]byte(req.CSR))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		proxywasm.SendHttpResponse(400, nil, []byte("Invalid PEM CSR"), -1)
		return types.ActionPause
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		proxywasm.SendHttpResponse(400, nil, []byte("Failed to parse CSR"), -1)
		return types.ActionPause
	}
	cn := csr.Subject.CommonName
	if sub != cn {
		proxywasm.SendHttpResponse(403, nil, []byte("sub does not match CSR CN"), -1)
		return types.ActionPause
	}
	return types.ActionContinue
}

func (*httpContext) OnHttpResponseHeaders(_ int, _ bool) types.Action {
	if err := proxywasm.AddHttpResponseHeader("x-proxy-wasm-go-sdk-example", "http_headers"); err != nil {
		proxywasm.LogCriticalf("failed to set response constant header: %v", err)
	}

	hs, err := proxywasm.GetHttpResponseHeaders()
	if err != nil {
		proxywasm.LogCriticalf("failed to get response headers: %v", err)
	}

	for _, h := range hs {
		proxywasm.LogInfof("response header <-- %s: %s", h[0], h[1])
	}
	return types.ActionContinue
}

func (*httpContext) OnHttpStreamDone() {
	proxywasm.LogInfof("%s finished", "wasm")
}
