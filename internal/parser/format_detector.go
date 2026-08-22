package parser

import "strings"

func Detect(data string) string {
	s := strings.TrimSpace(data)
	if strings.HasPrefix(s, "[") || strings.HasPrefix(s, "{") {
		return "json"
	}
	if strings.HasPrefix(s, "---") || strings.Contains(s, "\n-") && strings.Contains(s, ":") {
		return "yaml"
	}
	return "csv"
}
