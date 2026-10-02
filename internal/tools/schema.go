package tools

// Risk levels for MCP tools.
const (
	RiskRead    = "READ"
	RiskWrite   = "WRITE"
	RiskExecute = "EXECUTE"
	RiskAdmin   = "ADMIN"
)

// obj builds a JSON Schema object node.
func obj(props map[string]any, required ...string) map[string]any {
	if required == nil {
		required = []string{}
	}
	return map[string]any{
		"type":                 "object",
		"properties":           props,
		"required":             required,
		"additionalProperties": false,
	}
}

func str(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

func enumStr(desc string, values ...string) map[string]any {
	return map[string]any{"type": "string", "description": desc, "enum": values}
}

func num(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

func boolean(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}

func strArray(desc string) map[string]any {
	return map[string]any{
		"type":        "array",
		"description": desc,
		"items":       map[string]any{"type": "string"},
	}
}

// repoProps are the project/repository coordinates shared by most tools.
func repoProps(extra map[string]any) map[string]any {
	props := map[string]any{
		"project":    str("Bitbucket 프로젝트 키 (예: AI)"),
		"repository": str("저장소 슬러그 (예: text2sql)"),
	}
	for k, v := range extra {
		props[k] = v
	}
	return props
}

// paging adds start/limit to a property map.
func paging(props map[string]any) map[string]any {
	props["start"] = num("페이지 시작 오프셋 (기본 0)")
	props["limit"] = num("페이지 크기 (기본 50, 최대 1000)")
	return props
}
