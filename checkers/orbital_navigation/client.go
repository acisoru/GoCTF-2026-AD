package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	junge "github.com/skipper-ad/junge-checkers"
	"github.com/skipper-ad/junge-checkers/httpx"
	o "github.com/skipper-ad/junge-checkers/require/options"
)

type serviceClient struct {
	c    *junge.C
	http *httpx.Client
}

type rpcEnvelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result"`
	Error  string          `json:"error"`
}

type registerResult struct {
	Token  string `json:"token"`
	UserID string `json:"user_id"`
}

func newServiceClient(c *junge.C, host string) *serviceClient {
	return &serviceClient{
		c: c,
		http: httpx.NewClient(
			c,
			serviceBaseURL(host),
			httpx.WithTimeout(5*time.Second),
			httpx.WithErrorBodySnippet(512),
		),
	}
}

func serviceBaseURL(host string) string {
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		return strings.TrimRight(host, "/")
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return "http://" + host
	}
	port := 8086
	if raw := os.Getenv("ORBIT_SERVICE_PORT"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 65535 {
			port = parsed
		}
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(port))
}

func (api *serviceClient) register(public string) registerResult {
	var result registerResult
	api.rpc("register", "", nil, &result, public, junge.StatusMumble)
	if result.Token == "" || result.UserID == "" {
		api.c.Mumble(public, "register returned an empty token or user_id")
	}
	return result
}

func (api *serviceClient) rpc(action, token string, fields map[string]any, target any, public string, failure junge.Status) {
	request := rpcRequest(action, token, fields)

	options := []o.Option{o.Status(failure)}
	var envelope rpcEnvelope
	api.http.JSON(api.http.PostJSON("/rpc", request), &envelope, public, options...)
	if !envelope.OK {
		api.fail(failure, public, fmt.Sprintf("RPC %s failed: %s", action, envelope.Error))
	}
	if target == nil {
		return
	}
	if len(envelope.Result) == 0 || string(envelope.Result) == "null" {
		api.fail(failure, public, fmt.Sprintf("RPC %s returned an empty result", action))
	}
	if err := json.Unmarshal(envelope.Result, target); err != nil {
		api.fail(failure, public, fmt.Sprintf("decode RPC %s result: %v", action, err))
	}
}

func (api *serviceClient) rpcError(action, token string, fields map[string]any, expected, public string, failure junge.Status) {
	response := api.http.PostJSON("/rpc", rpcRequest(action, token, fields))
	api.http.ExpectStatus(response, 400, public, o.Status(failure))
	defer response.Body.Close()

	var envelope rpcEnvelope
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		api.fail(failure, public, fmt.Sprintf("decode rejected RPC %s response: %v", action, err))
	}
	if envelope.OK || !strings.Contains(envelope.Error, expected) {
		api.fail(failure, public, fmt.Sprintf("RPC %s returned unexpected error: %q", action, envelope.Error))
	}
}

func rpcRequest(action, token string, fields map[string]any) map[string]any {
	request := make(map[string]any, len(fields)+2)
	for key, value := range fields {
		request[key] = value
	}
	request["action"] = action
	if token != "" {
		request["token"] = token
	}
	return request
}

func (api *serviceClient) uploadPackage(token, packageID string, data []byte, public string, failure junge.Status) {
	path := "/packages/" + url.PathEscape(packageID) + "/content"
	client := httpx.NewClient(
		api.c,
		api.http.BaseURL,
		httpx.WithTimeout(5*time.Second),
		httpx.WithBearerToken(token),
		httpx.WithErrorBodySnippet(512),
	)
	client.ExpectStatus(
		client.DoBytes("PUT", path, data, "application/x-tar"),
		200,
		public,
		o.Status(failure),
	)
}

func (api *serviceClient) fail(status junge.Status, public, private string) {
	api.c.Finish(status, public, private)
}
