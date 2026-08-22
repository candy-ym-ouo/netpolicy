package parser

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"netpolicy/internal/domain/model"
	"strconv"
	"strings"
)

func Parse(format, data string) ([]model.Rule, []ValidationError) {
	if format == "auto" || format == "" {
		format = Detect(data)
	}
	var rules []model.Rule
	var errs []ValidationError
	switch format {
	case "json":
		if err := json.Unmarshal([]byte(data), &rules); err != nil {
			return nil, []ValidationError{{1, "body", err.Error()}}
		}
	case "csv":
		reader := csv.NewReader(strings.NewReader(data))
		header, err := reader.Read()
		if err != nil {
			return nil, []ValidationError{{1, "header", err.Error()}}
		}
		for line := 2; ; line++ {
			row, err := reader.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				errs = append(errs, ValidationError{line, "row", err.Error()})
				continue
			}
			rules = append(rules, csvRule(header, row))
		}
	case "yaml":
		rules, errs = parseYAML(data)
	default:
		return nil, []ValidationError{{1, "format", "unsupported format"}}
	}
	seen := map[string]bool{}
	out := make([]model.Rule, 0, len(rules))
	for i, r := range rules {
		r = r.Normalize()
		var err error
		r.Src, err = model.CanonicalCIDR(r.Src)
		r.Dst, err = model.CanonicalCIDR(r.Dst)
		if seen[r.ID] {
			errs = append(errs, ValidationError{i + 1, "id", "duplicate id"})
		}
		seen[r.ID] = true
		if err = Validate(r, i+1); err != nil {
			errs = append(errs, ValidationError{i + 1, "rule", err.Error()})
		}
		out = append(out, r)
	}
	return out, errs
}
func csvRule(header, row []string) model.Rule {
	r := model.Rule{}
	for i, key := range header {
		if i >= len(row) {
			break
		}
		v := row[i]
		switch strings.TrimSpace(key) {
		case "id":
			r.ID = v
		case "policySet":
			r.PolicySet = v
		case "priority":
			r.Priority, _ = strconv.Atoi(v)
		case "action":
			r.Action = v
		case "src":
			r.Src = v
		case "dst":
			r.Dst = v
		case "protocol":
			r.Protocol = v
		case "portFrom":
			r.PortFrom, _ = strconv.Atoi(v)
		case "portTo":
			r.PortTo, _ = strconv.Atoi(v)
		case "description":
			r.Description = v
		case "source":
			r.Source = v
		}
	}
	return r
}
func parseYAML(data string) ([]model.Rule, []ValidationError) {
	var result []model.Rule
	var current model.Rule
	active := false
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || line == "---" {
			continue
		}
		if line == "-" || strings.HasPrefix(line, "- ") {
			if active {
				result = append(result, current)
			}
			current = model.Rule{}
			active = true
			line = strings.TrimSpace(strings.TrimPrefix(line, "-"))
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := strings.TrimSpace(parts[0]), strings.Trim(strings.TrimSpace(parts[1]), "\"'")
		switch key {
		case "id":
			current.ID = value
		case "policySet":
			current.PolicySet = value
		case "priority":
			current.Priority, _ = strconv.Atoi(value)
		case "action":
			current.Action = value
		case "src":
			current.Src = value
		case "dst":
			current.Dst = value
		case "protocol":
			current.Protocol = value
		case "portFrom":
			current.PortFrom, _ = strconv.Atoi(value)
		case "portTo":
			current.PortTo, _ = strconv.Atoi(value)
		case "description":
			current.Description = value
		}
	}
	if active {
		result = append(result, current)
	}
	if len(result) == 0 {
		return nil, []ValidationError{{1, "body", fmt.Sprint("no YAML rules")}}
	}
	return result, nil
}
