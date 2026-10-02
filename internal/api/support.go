package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/hkjang/bbmcp/internal/aiproxy"
	"github.com/hkjang/bbmcp/internal/httpx"
	"github.com/hkjang/bbmcp/internal/settings"
)

// apiError carries an HTTP status alongside a message.
type apiError struct {
	status  int
	message string
}

func (e *apiError) Error() string { return e.message }

func errBadRequest(msg string) error { return &apiError{http.StatusBadRequest, msg} }
func errForbidden(msg string) error  { return &apiError{http.StatusForbidden, msg} }
func errNotFound(msg string) error   { return &apiError{http.StatusNotFound, msg} }

func writeErr(w http.ResponseWriter, err error) {
	if ae, ok := err.(*apiError); ok {
		httpx.Fail(w, ae.status, ae.message)
		return
	}
	httpx.Fail(w, http.StatusInternalServerError, err.Error())
}

func queryInt(r *http.Request, name string, def int) int {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return n
}

func queryBoolPtr(r *http.Request, name string) *bool {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return nil
	}
	v := raw == "true" || raw == "1"
	return &v
}

// aiRequest mirrors aiproxy.Request at the HTTP boundary.
type aiRequest struct {
	Messages    []aiproxy.Message `json:"messages"`
	Model       string            `json:"model,omitempty"`
	MaxTokens   int               `json:"maxTokens,omitempty"`
	Temperature *float64          `json:"temperature,omitempty"`
	TopP        *float64          `json:"topP,omitempty"`
	System      string            `json:"system,omitempty"`
}

func (a aiRequest) toProxyRequest() aiproxy.Request {
	return aiproxy.Request{
		Messages: a.Messages, Model: a.Model, MaxTokens: a.MaxTokens,
		Temperature: a.Temperature, TopP: a.TopP, System: a.System,
	}
}

// aiEvent is the SSE payload shape sent to the browser.
type aiEvent = aiproxy.Event

func maxTokenCeiling() int { return settings.MaxTokenCeiling }

// writeSSE writes one server-sent event.
func writeSSE(w http.ResponseWriter, event string, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	if event != "" {
		fmt.Fprintf(w, "event: %s\n", event)
	}
	fmt.Fprintf(w, "data: %s\n\n", body)
}

// remarshal re-decodes a generic JSON object into a typed struct.
func remarshal(in map[string]any, out any) error {
	if in == nil {
		return nil
	}
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}
