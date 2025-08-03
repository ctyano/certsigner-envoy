package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/tidwall/gjson"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm/types"
)

type CrypkiCSRRequest struct {
	CSR string `json:"csr"`
}

type CFSSLCSRRequest struct {
	CSR string `json:"certificate_request"`
}

func main() {}
func init() {
	proxywasm.SetVMContext(&vmContext{})
}

// vmContext implements types.VMContext.
type vmContext struct {
	// Embed the default VM context here,
	// so that we don't need to reimplement all the methods.
	types.DefaultVMContext
}

// NewPluginContext implements types.VMContext.
func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	return &pluginContext{}
}

// pluginContext implements types.PluginContext.
type pluginContext struct {
	// Embed the default plugin context here,
	// so that we don't need to reimplement all the methods.
	types.DefaultPluginContext

	// nameClaim and userPrefix are are configured via plugin configuration during OnPluginStart.
	nameClaim  string
	userPrefix string
	signerType string
}

// NewHttpContext implements types.PluginContext.
func (p *pluginContext) NewHttpContext(contextID uint32) types.HttpContext {
	return &httpContext{
		contextID:  contextID,
		nameClaim:  p.nameClaim,
		userPrefix: p.userPrefix,
		signerType: p.signerType,
	}
}

type httpContext struct {
	types.DefaultHttpContext
	contextID uint32

	// nameClaim and userPrefix are are configured via plugin configuration during OnPluginStart.
	nameClaim  string
	userPrefix string
	signerType string
}

// OnPluginStart implements types.PluginContext.
// Note that this parses the json data by gjson, since TinyGo doesn't support encoding/json.
// You can also try https://github.com/mailru/easyjson, which supports decoding to a struct.
// configuration:
//   "@type": type.googleapis.com/google.protobuf.StringValue
//   value: |
//     {
//       "user_prefix": "<prefix to prepend to the jwt claim to compare with csr subject cn as an athenz user name. e.g. user.>",
//       "claim": "<jwt claim name to extract athenz user name>",
//       "signer": "<name for the certificate signer product ("crypki" or "cfssl")>"
//     }
func (p *pluginContext) OnPluginStart(pluginConfigurationSize int) types.OnPluginStartStatus {
	proxywasm.LogDebug("Loading plugin config")
	data, err := proxywasm.GetPluginConfiguration()
	if data == nil {
		return types.OnPluginStartStatusOK
	}

	if err != nil {
		proxywasm.LogCriticalf("Error reading plugin configuration: %v", err)
		return types.OnPluginStartStatusFailed
	}

	if !gjson.Valid(string(data)) {
		proxywasm.LogCritical(`Invalid configuration format; expected {"claim": "<claim to extract the user name>"}`)
		return types.OnPluginStartStatusFailed
	}

	p.nameClaim = strings.TrimSpace(gjson.Get(string(data), "claim").Str)
	p.userPrefix = strings.TrimSpace(gjson.Get(string(data), "user_prefix").Str)
	p.signerType = strings.TrimSpace(gjson.Get(string(data), "signer").Str)

	if p.nameClaim == "" {
		proxywasm.LogCritical(`Invalid configuration format; expected {"claim": "<prefix to prepend to the jwt claim to compare with csr subject cn as an athenz user name. e.g. user.>"}`)
		return types.OnPluginStartStatusFailed
	}
	if p.userPrefix == "" {
		proxywasm.LogCritical(`Invalid configuration format; expected {"user_prefix": "<jwt claim name to extract athenz user name>"}`)
		return types.OnPluginStartStatusFailed
	}
	if p.signerType != "crypki" && p.signerType != "cfssl" {
		proxywasm.LogCritical(`Invalid configuration format; expected {"signer": "<\"crypki\" or \"cfssl\">"}`)
		return types.OnPluginStartStatusFailed
	}

	proxywasm.LogInfof("JWT claim name to extract the user name: %s", p.nameClaim)
	proxywasm.LogInfof("Prefix string to prepend to user name: %s", p.userPrefix)
	proxywasm.LogInfof("Signer type: %s", p.signerType)

	return types.OnPluginStartStatusOK
}

// OnHttpRequestHeaders implements types.HttpContext.
func (ctx *httpContext) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	hs, err := proxywasm.GetHttpRequestHeaders()
	if err != nil {
		proxywasm.LogCriticalf("Failed to get request headers: %v", err)
	}

	for _, h := range hs {
		proxywasm.LogInfof("Request header --> %s: %s", h[0], h[1])
	}
	auth, err := proxywasm.GetHttpRequestHeader("authorization")
	if err != nil || !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		proxywasm.LogWarnf("Missing or invalid authorization header")
		proxywasm.SendHttpResponse(401, nil, []byte("Invalid authorization header"), -1)
		proxywasm.SetProperty([]string{"result"}, []byte("failure"))
		return types.ActionPause
	}
	// Trim the first 7 characters and other spaces
	rawJWT := strings.TrimSpace(auth[8:])

	// JWT: not validated, just parsed for name
	// This plugin expects the JWT to be validated with Envoy JWT Filter
	token, _, err := new(jwt.Parser).ParseUnverified(rawJWT, jwt.MapClaims{})
	if err != nil {
		proxywasm.LogWarnf("Invalid JWT: %s", rawJWT)
		proxywasm.SendHttpResponse(401, nil, []byte("Invalid JWT"), -1)
		proxywasm.SetProperty([]string{"result"}, []byte("failure"))
		return types.ActionPause
	}
	claims := token.Claims.(jwt.MapClaims)
	name, ok := claims[ctx.nameClaim].(string)
	if !ok {
		proxywasm.LogWarnf("No %s claim in JWT", ctx.nameClaim)
		proxywasm.SendHttpResponse(403, nil, []byte(fmt.Sprintf("No %s claim in JWT", ctx.nameClaim)), -1)
		proxywasm.SetProperty([]string{"result"}, []byte("failure"))
		return types.ActionPause
	}
	// Save name for later in context
	proxywasm.LogDebugf("Saved the user name in request_name property: %s", name)
	proxywasm.SetProperty([]string{"request_name"}, []byte(name))
	return types.ActionContinue
}

// OnHttpRequestBody implements types.HttpContext.
func (ctx *httpContext) OnHttpRequestBody(bodySize int, endOfStream bool) types.Action {
	if !endOfStream {
		proxywasm.SetProperty([]string{"result"}, []byte("failure"))
		return types.ActionPause
	}
	// Get name claim from context property
	nameBytes, _ := proxywasm.GetProperty([]string{"request_name"})
	name := string(nameBytes)
	body, err := proxywasm.GetHttpRequestBody(0, bodySize)
	if err != nil {
		proxywasm.LogWarnf("Failed to read body")
		proxywasm.SendHttpResponse(400, nil, []byte("Failed to read body"), -1)
		proxywasm.SetProperty([]string{"result"}, []byte("failure"))
		return types.ActionPause
	}
	var req map[string]interface{}
	if err := json.Unmarshal(body, &req); err != nil {
		proxywasm.LogWarnf("Invalid JSON")
		proxywasm.SendHttpResponse(400, nil, []byte("Invalid JSON"), -1)
		proxywasm.SetProperty([]string{"result"}, []byte("failure"))
		return types.ActionPause
	}
	csrString := ""
	switch ctx.signerType {
	case "crypki":
		if val, ok := req["csr"].(string); ok {
			csrString = val
		}
	case "cfssl":
		if val, ok := req["certificate_request"].(string); ok {
			csrString = val
		}
	}
	if csrString == "" {
		proxywasm.LogWarnf("Missing CSR in JSON")
		proxywasm.SendHttpResponse(400, nil, []byte("Missing CSR in JSON"), -1)
		proxywasm.SetProperty([]string{"result"}, []byte("failure"))
		return types.ActionPause
	}
	block, _ := pem.Decode([]byte(csrString))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		proxywasm.LogWarnf("Invalid PEM CSR: %s", csrString)
		proxywasm.SendHttpResponse(400, nil, []byte("Invalid PEM CSR"), -1)
		proxywasm.SetProperty([]string{"result"}, []byte("failure"))
		return types.ActionPause
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		proxywasm.LogWarnf("Failed to parse CSR: %s", csrString)
		proxywasm.SendHttpResponse(400, nil, []byte("Failed to parse CSR"), -1)
		proxywasm.SetProperty([]string{"result"}, []byte("failure"))
		return types.ActionPause
	}
	cn := csr.Subject.CommonName
	if ctx.userPrefix+name != cn {
		proxywasm.LogWarnf("Claim %s does not match CSR CN: %s[%s], cn[%s]", ctx.nameClaim, ctx.nameClaim, name, cn)
		proxywasm.SendHttpResponse(403, nil, []byte(fmt.Sprintf("The name %s in %s claim does not match CSR CN %s", name, ctx.nameClaim, cn)), -1)
		proxywasm.SetProperty([]string{"result"}, []byte("failure"))
		return types.ActionPause
	}
	proxywasm.SetProperty([]string{"result"}, []byte("success"))
	return types.ActionContinue
}

// OnHttpResponseHeaders implements types.HttpContext.
func (*httpContext) OnHttpResponseHeaders(_ int, _ bool) types.Action {
	resultBytes, _ := proxywasm.GetProperty([]string{"result"})
	if err := proxywasm.AddHttpResponseHeader("x-certsigner-envoy-wasm", string(resultBytes)); err != nil {
		proxywasm.LogCriticalf("Failed to set response constant header: %v", err)
	}

	hs, err := proxywasm.GetHttpResponseHeaders()
	if err != nil {
		proxywasm.LogCriticalf("Failed to get response headers: %v", err)
	}

	for _, h := range hs {
		proxywasm.LogInfof("Response header <-- %s: %s", h[0], h[1])
	}
	return types.ActionContinue
}

// OnHttpStreamDone implements types.HttpContext.
func (ctx *httpContext) OnHttpStreamDone() {
	proxywasm.LogInfof("%s finished", "certsigner-envoy-wasm")
}
