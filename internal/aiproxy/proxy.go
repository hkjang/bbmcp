// Package aiproxy streams AI completions to the browser.
//
// Streaming is the default path: the upstream provider is always called with
// stream=true and relayed as server-sent events, so a long review answer shows
// up progressively instead of blocking the UI. max_tokens is clamped to the
// configured ceiling (up to 256k).
package aiproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hkjang/bbmcp/internal/settings"
)

// Message is one chat turn.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Request is the browser-facing payload.
type Request struct {
	Messages    []Message `json:"messages"`
	Model       string    `json:"model,omitempty"`
	MaxTokens   int       `json:"maxTokens,omitempty"`
	Temperature *float64  `json:"temperature,omitempty"`
	TopP        *float64  `json:"topP,omitempty"`
	System      string    `json:"system,omitempty"`
	Stream      *bool     `json:"stream,omitempty"`
}

// Event is one streamed chunk handed to the caller.
type Event struct {
	Type  string `json:"type"` // delta | done | error | usage
	Text  string `json:"text,omitempty"`
	Error string `json:"error,omitempty"`
	Model string `json:"model,omitempty"`
	Usage any    `json:"usage,omitempty"`
}

// Proxy talks to the configured AI provider.
type Proxy struct{ store *settings.Store }

// New builds the proxy.
func New(store *settings.Store) *Proxy { return &Proxy{store: store} }

// Config returns the current AI settings with the key decrypted.
func (p *Proxy) Config(ctx context.Context) (settings.AI, string, error) {
	cfg, err := p.store.AI(ctx)
	if err != nil {
		return cfg, "", err
	}
	key, err := p.store.Reveal(cfg.APIKeyEnc)
	return cfg, key, err
}

// Stream calls the provider and invokes emit for every event.
func (p *Proxy) Stream(ctx context.Context, req Request, emit func(Event) error) error {
	cfg, apiKey, err := p.Config(ctx)
	if err != nil {
		return err
	}
	if !cfg.Enabled {
		return errors.New("AI 기능이 비활성화되어 있습니다")
	}
	if len(req.Messages) == 0 {
		return errors.New("messages 가 비어 있습니다")
	}

	model := req.Model
	if model == "" {
		model = cfg.Model
	}
	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = cfg.MaxTokens
	}
	ceiling := cfg.ContextLimit
	if ceiling <= 0 || ceiling > settings.MaxTokenCeiling {
		ceiling = settings.MaxTokenCeiling
	}
	if maxTokens > ceiling {
		maxTokens = ceiling
	}
	system := req.System
	if system == "" {
		system = cfg.SystemPrompt
	}
	temperature := cfg.Temperature
	if req.Temperature != nil {
		temperature = *req.Temperature
	}
	topP := cfg.TopP
	if req.TopP != nil {
		topP = *req.TopP
	}

	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 300 * time.Second
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}

	switch strings.ToLower(cfg.Provider) {
	case "anthropic":
		return p.streamAnthropic(ctx, client, cfg, apiKey, model, system, maxTokens, temperature, topP, req, emit)
	default:
		return p.streamOpenAICompatible(ctx, client, cfg, apiKey, model, system, maxTokens, temperature, topP, req, emit)
	}
}

func (p *Proxy) streamAnthropic(ctx context.Context, client *http.Client, cfg settings.AI,
	apiKey, model, system string, maxTokens int, temperature, topP float64,
	req Request, emit func(Event) error) error {

	msgs := make([]map[string]any, 0, len(req.Messages))
	for _, m := range req.Messages {
		role := m.Role
		if role != "assistant" {
			role = "user"
		}
		msgs = append(msgs, map[string]any{"role": role, "content": m.Content})
	}
	body := map[string]any{
		"model":       model,
		"max_tokens":  maxTokens,
		"messages":    msgs,
		"stream":      true,
		"temperature": temperature,
	}
	if topP > 0 && topP < 1 {
		body["top_p"] = topP
	}
	if system != "" {
		body["system"] = system
	}

	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		base = "https://api.anthropic.com"
	}
	httpReq, err := p.newRequest(ctx, base+"/v1/messages", body)
	if err != nil {
		return err
	}
	httpReq.Header.Set("x-api-key", apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("AI 호출 실패: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return upstreamError(resp)
	}

	return relaySSE(resp.Body, func(payload []byte) error {
		var ev struct {
			Type  string `json:"type"`
			Delta struct {
				Text string `json:"text"`
			} `json:"delta"`
			Message struct {
				Usage any `json:"usage"`
			} `json:"message"`
			Usage any `json:"usage"`
		}
		if err := json.Unmarshal(payload, &ev); err != nil {
			return nil
		}
		switch ev.Type {
		case "content_block_delta":
			if ev.Delta.Text != "" {
				return emit(Event{Type: "delta", Text: ev.Delta.Text})
			}
		case "message_delta":
			if ev.Usage != nil {
				return emit(Event{Type: "usage", Usage: ev.Usage})
			}
		case "message_stop":
			return emit(Event{Type: "done", Model: model})
		case "error":
			return emit(Event{Type: "error", Error: string(payload)})
		}
		return nil
	}, func() error { return emit(Event{Type: "done", Model: model}) })
}

func (p *Proxy) streamOpenAICompatible(ctx context.Context, client *http.Client, cfg settings.AI,
	apiKey, model, system string, maxTokens int, temperature, topP float64,
	req Request, emit func(Event) error) error {

	msgs := make([]map[string]any, 0, len(req.Messages)+1)
	if system != "" {
		msgs = append(msgs, map[string]any{"role": "system", "content": system})
	}
	for _, m := range req.Messages {
		msgs = append(msgs, map[string]any{"role": m.Role, "content": m.Content})
	}
	body := map[string]any{
		"model":       model,
		"messages":    msgs,
		"stream":      true,
		"max_tokens":  maxTokens,
		"temperature": temperature,
	}
	if topP > 0 && topP < 1 {
		body["top_p"] = topP
	}

	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		return errors.New("AI 기본 URL이 설정되지 않았습니다")
	}
	url := base + "/v1/chat/completions"
	if strings.HasSuffix(base, "/v1") {
		url = base + "/chat/completions"
	}
	httpReq, err := p.newRequest(ctx, url, body)
	if err != nil {
		return err
	}
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("AI 호출 실패: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return upstreamError(resp)
	}

	return relaySSE(resp.Body, func(payload []byte) error {
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
				FinishReason *string `json:"finish_reason"`
			} `json:"choices"`
			Usage any `json:"usage"`
		}
		if err := json.Unmarshal(payload, &chunk); err != nil {
			return nil
		}
		for _, ch := range chunk.Choices {
			if ch.Delta.Content != "" {
				if err := emit(Event{Type: "delta", Text: ch.Delta.Content}); err != nil {
					return err
				}
			}
		}
		if chunk.Usage != nil {
			return emit(Event{Type: "usage", Usage: chunk.Usage})
		}
		return nil
	}, func() error { return emit(Event{Type: "done", Model: model}) })
}

func (p *Proxy) newRequest(ctx context.Context, url string, body map[string]any) (*http.Request, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	return req, nil
}

func upstreamError(resp *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	msg := strings.TrimSpace(string(raw))
	if len(msg) > 500 {
		msg = msg[:500] + "…"
	}
	return fmt.Errorf("AI 제공자 오류 %d: %s", resp.StatusCode, msg)
}

// relaySSE parses an SSE body and invokes onData for each data payload.
func relaySSE(body io.Reader, onData func([]byte) error, onEOF func() error) error {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" || strings.HasPrefix(line, ":") {
			continue
		}
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		if err := onData([]byte(payload)); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return onEOF()
}

// Test performs a minimal non-streaming style check of the configuration.
func (p *Proxy) Test(ctx context.Context) (string, error) {
	var sb strings.Builder
	err := p.Stream(ctx, Request{
		Messages:  []Message{{Role: "user", Content: "연결 확인용입니다. '확인' 한 단어로만 답하십시오."}},
		MaxTokens: 64,
	}, func(e Event) error {
		if e.Type == "delta" {
			sb.WriteString(e.Text)
		}
		if e.Type == "error" {
			return errors.New(e.Error)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(sb.String()), nil
}
