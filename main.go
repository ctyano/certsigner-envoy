package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"strings"

	"github.com/tidwall/gjson"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm/types"
)

type CSRRequest struct {
	CSR string `json:"csr"`
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
}

// NewHttpContext implements types.PluginContext.
func (p *pluginContext) NewHttpContext(contextID uint32) types.HttpContext {
	return &httpContext{
		contextID:  contextID,
		nameClaim:  p.nameClaim,
		userPrefix: p.userPrefix,
	}
}

type httpContext struct {
	types.DefaultHttpContext
	contextID uint32

	// nameClaim and userPrefix are are configured via plugin configuration during OnPluginStart.
	nameClaim  string
	userPrefix string
}

// networkContext implements types.TcpContext.
type networkContext struct {
	// Embed the default tcp context here,
	// so that we don't need to reimplement all the methods.
	types.DefaultTcpContext
}

// OnPluginStart implements types.PluginContext.
// Note that this parses the json data by gjson, since TinyGo doesn't support encoding/json.
// You can also try https://github.com/mailru/easyjson, which supports decoding to a struct.
// configuration:
//   "@type": type.googleapis.com/google.protobuf.StringValue
//   value: |
//     {
//       "user_prefix": "<prefix to prepend to the jwt claim to compare with csr subject cn as an athenz user name. e.g. user.>",
//       "claim": "<jwt claim name to extract athenz user name>"
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

	if p.nameClaim == "" {
		proxywasm.LogCritical(`Invalid configuration format; expected {"claim": "<prefix to prepend to the jwt claim to compare with csr subject cn as an athenz user name. e.g. user.>"}`)
		return types.OnPluginStartStatusFailed
	}
	if p.userPrefix == "" {
		proxywasm.LogCritical(`Invalid configuration format; expected {"user_prefix": "<jwt claim name to extract athenz user name>"}`)
		return types.OnPluginStartStatusFailed
	}

	proxywasm.LogInfof("JWT claim name to extract the user name: %s", p.nameClaim)
	proxywasm.LogInfof("Prefix string to prepend to user name: %s", p.userPrefix)

	return types.OnPluginStartStatusOK
}

// NewTcpContext implements types.PluginContext.
func (ctx *pluginContext) NewTcpContext(contextID uint32) types.TcpContext {
	return &networkContext{}
}

// OnUpstreamData implements types.TcpContext.
func (ctx *networkContext) OnDownstreamData(dataSize int, endOfStream bool) types.Action {
	if dataSize == 0 {
		return types.ActionContinue
	}

	address, err := proxywasm.GetProperty([]string{"source", "address"})
	if err != nil {
		proxywasm.LogWarnf("failed to get upstream remote address: %v", err)
	}
	proxywasm.LogInfof("remote address: %s", string(address))

	// Extract just the IP (handle IPv6 addresses)
	remoteAddr, err := proxywasm.GetProperty([]string{"downstream", "address"})
	if err != nil {
		proxywasm.LogCriticalf("Failed to get remote address: %v", err)
		proxywasm.SendHttpResponse(403, nil, []byte(fmt.Sprintf("Failed to get remote address: %v", err)), -1)
		proxywasm.SetProperty([]string{"result"}, []byte("failure"))
		return types.ActionPause
	}
	// Save remote address for later in context
	proxywasm.SetProperty([]string{"remote_address"}, remoteAddr)
	proxywasm.LogDebugf("Saved the remote address in remote_address property: %s", remoteAddr)

	return types.ActionContinue
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
		proxywasm.SendHttpResponse(401, nil, []byte("Missing or invalid authorization header"), -1)
		proxywasm.SetProperty([]string{"result"}, []byte("failure"))
		return types.ActionPause
	}
	// JWT: not validated, just parsed for name
	// This plugin expects the JWT to be validated with Envoy JWT Filter
	rawJWT := strings.TrimPrefix(auth, "Bearer ")
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
	proxywasm.SetProperty([]string{"request_name"}, []byte(name))
	proxywasm.LogDebugf("Saved the user name in request_name property: %s", name)

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
	remoteAddressBytes, _ := proxywasm.GetProperty([]string{"remote_address"})
	name := string(nameBytes)
	remoteAddr := string(remoteAddressBytes)

	// Get name from CSR Subject CN
	body, err := proxywasm.GetHttpRequestBody(0, bodySize)
	if err != nil {
		proxywasm.LogWarnf("Failed to read body")
		proxywasm.SendHttpResponse(400, nil, []byte("Failed to read body"), -1)
		proxywasm.SetProperty([]string{"result"}, []byte("failure"))
		return types.ActionPause
	}
	var req CSRRequest
	if err := json.Unmarshal(body, &req); err != nil || req.CSR == "" {
		proxywasm.LogWarnf("Invalid JSON or missing csr")
		proxywasm.SendHttpResponse(400, nil, []byte("Invalid JSON or missing csr"), -1)
		proxywasm.SetProperty([]string{"result"}, []byte("failure"))
		return types.ActionPause
	}
	block, _ := pem.Decode([]byte(req.CSR))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		proxywasm.LogWarnf("Invalid PEM CSR: %s", req.CSR)
		proxywasm.SendHttpResponse(400, nil, []byte("Invalid PEM CSR"), -1)
		proxywasm.SetProperty([]string{"result"}, []byte("failure"))
		return types.ActionPause
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		proxywasm.LogWarnf("Failed to parse CSR: %s", req.CSR)
		proxywasm.SendHttpResponse(400, nil, []byte("Failed to parse CSR"), -1)
		proxywasm.SetProperty([]string{"result"}, []byte("failure"))
		return types.ActionPause
	}
	cn := csr.Subject.CommonName

	// Compare name with CSR Subject CN
	if ctx.userPrefix+name != cn {
		proxywasm.LogWarnf("Claim %s does not match CSR CN: %s[%s], cn[%s]", ctx.nameClaim, ctx.nameClaim, name, cn)
		proxywasm.SendHttpResponse(403, nil, []byte(fmt.Sprintf("The name %s in %s claim does not match CSR CN %s", name, ctx.nameClaim, cn)), -1)
		proxywasm.SetProperty([]string{"result"}, []byte("failure"))
		return types.ActionPause
	}

	// CSR should not contain any SAN DNS entry
	if len(csr.DNSNames) > 0 {
		proxywasm.LogWarnf("CSR should not container any SAN DNS entries: %v", csr.DNSNames)
		proxywasm.SendHttpResponse(403, nil, []byte(fmt.Sprintf("CSR should not container any SAN DNS entries: %v", csr.DNSNames)), -1)
		proxywasm.SetProperty([]string{"result"}, []byte("failure"))
		return types.ActionPause
	}

	// CSR should not contain any SAN Email entry
	if len(csr.EmailAddresses) > 0 {
		proxywasm.LogWarnf("CSR should not container any SAN Email entries: %v", csr.DNSNames)
		proxywasm.SendHttpResponse(403, nil, []byte(fmt.Sprintf("CSR should not container any SAN Email entries: %v", csr.DNSNames)), -1)
		proxywasm.SetProperty([]string{"result"}, []byte("failure"))
		return types.ActionPause
	}

	// CSR should only contain valid SAN IP entry
	if len(csr.IPAddresses) > 0 {
		//host, _, err := net.SplitHostPort(remoteAddr)
		//if err != nil {
		//	proxywasm.LogCriticalf("Failed to split host/port: %v", err)
		//	proxywasm.SendHttpResponse(403, nil, []byte(fmt.Sprintf("Failed to split host/port: %v", err)), -1)
		//	proxywasm.SetProperty([]string{"result"}, []byte("failure"))
		//	return types.ActionPause
		//}
		// Parse the IP as net.IP
		clientIP := net.ParseIP(remoteAddr)
		if clientIP == nil {
			proxywasm.LogCriticalf("Invalid IP: %s", remoteAddr)
			proxywasm.SendHttpResponse(403, nil, []byte(fmt.Sprintf("Invalid IP: %s", remoteAddr)), -1)
			proxywasm.SetProperty([]string{"result"}, []byte("failure"))
			return types.ActionPause
		}

		for _, ip := range csr.IPAddresses {
			if !ip.Equal(clientIP) {
				proxywasm.LogWarnf("CSR should only contain SAN IP entry as [%s]: %v", clientIP, csr.IPAddresses)
				proxywasm.SendHttpResponse(403, nil, []byte(fmt.Sprintf("CSR should only contain SAN IP entry as [%s]: %v", clientIP, csr.IPAddresses)), -1)
				proxywasm.SetProperty([]string{"result"}, []byte("failure"))
				return types.ActionPause
			}
		}
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
