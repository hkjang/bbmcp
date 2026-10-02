// Package tools defines the MCP tool surface over Bitbucket and the pipeline
// that authorises every call: identity → policy → effective permission →
// approval → service-account REST.
package tools

import (
	"errors"
	"fmt"
	"strings"
)

// Args is a decoded MCP tool argument map.
type Args map[string]any

// String returns a required string argument.
func (a Args) String(name string) (string, error) {
	v, ok := a[name]
	if !ok || v == nil {
		return "", fmt.Errorf("필수 인자 %s 가 없습니다", name)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("인자 %s 는 문자열이어야 합니다", name)
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("인자 %s 가 비어 있습니다", name)
	}
	return s, nil
}

// OptString returns an optional string argument.
func (a Args) OptString(name, def string) string {
	if v, ok := a[name]; ok {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return def
}

// Int returns a required integer argument.
func (a Args) Int(name string) (int, error) {
	v, ok := a[name]
	if !ok || v == nil {
		return 0, fmt.Errorf("필수 인자 %s 가 없습니다", name)
	}
	n, ok := toInt(v)
	if !ok {
		return 0, fmt.Errorf("인자 %s 는 정수여야 합니다", name)
	}
	return n, nil
}

// OptInt returns an optional integer argument.
func (a Args) OptInt(name string, def int) int {
	if v, ok := a[name]; ok && v != nil {
		if n, ok := toInt(v); ok {
			return n
		}
	}
	return def
}

// OptBool returns an optional boolean argument.
func (a Args) OptBool(name string, def bool) bool {
	if v, ok := a[name]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return def
}

// StringSlice returns an optional string list argument.
func (a Args) StringSlice(name string) []string {
	v, ok := a[name]
	if !ok || v == nil {
		return nil
	}
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	case string:
		parts := strings.Split(t, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if strings.TrimSpace(p) != "" {
				out = append(out, strings.TrimSpace(p))
			}
		}
		return out
	}
	return nil
}

func toInt(v any) (int, bool) {
	switch t := v.(type) {
	case int:
		return t, true
	case int32:
		return int(t), true
	case int64:
		return int(t), true
	case float64:
		return int(t), true
	case float32:
		return int(t), true
	case string:
		var n int
		if _, err := fmt.Sscanf(strings.TrimSpace(t), "%d", &n); err == nil {
			return n, true
		}
	}
	return 0, false
}

// ErrNotImplemented marks a tool that is registered but intentionally off.
var ErrNotImplemented = errors.New("이 도구는 활성화되지 않았습니다")
