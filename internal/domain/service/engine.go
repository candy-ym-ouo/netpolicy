package service

import (
	"encoding/json"
	"fmt"
	"net"
	"netpolicy/internal/domain/model"
	"netpolicy/internal/storage"
)

type Engine struct {
	Repo          storage.Repository
	DefaultAction string
}

func (e Engine) Analyze(kind string, rules []model.Rule, params map[string]any) (any, error) {
	switch kind {
	case "coverage":
		var t []string
		if v, ok := params["targetSpace"].([]any); ok {
			for _, x := range v {
				s, ok := x.(string)
				if !ok {
					return nil, fmt.Errorf("targetSpace must contain strings")
				}
				if _, err := model.CIDR(s); err != nil {
					return nil, fmt.Errorf("invalid targetSpace CIDR %q", s)
				}
				t = append(t, s)
			}
		}
		return Coverage(rules, t, e.DefaultAction), nil
	case "conflicts":
		return Conflicts(rules), nil
	case "redundancy":
		return Redundancy(rules), nil
	case "reachability":
		var s model.Scenario
		if params == nil || params["scenario"] == nil {
			return nil, fmt.Errorf("scenario is required")
		}
		b, _ := json.Marshal(params["scenario"])
		if err := json.Unmarshal(b, &s); err != nil {
			return nil, err
		}
		if err := validateScenario(s); err != nil {
			return nil, err
		}
		return Reachability(rules, s, e.DefaultAction), nil
	case "matrix":
		return e.matrix(rules, params)
	default:
		return nil, fmt.Errorf("unsupported analysis type %s", kind)
	}
}

func (e Engine) matrix(rules []model.Rule, params map[string]any) (map[string]any, error) {
	sources, err := stringList(params, "sources")
	if err != nil {
		return nil, err
	}
	targets, err := stringList(params, "targets")
	if err != nil {
		return nil, err
	}
	ports, err := intList(params, "ports")
	if err != nil {
		return nil, err
	}
	protocol := params["protocol"].(string)
	if len(sources) == 0 || len(targets) == 0 || len(ports) == 0 {
		return nil, fmt.Errorf("sources, targets and ports are required")
	}
	results := make([]model.ReachabilityResult, 0, len(sources)*len(targets)*len(ports))
	for _, source := range sources {
		for _, target := range targets {
			for _, port := range ports {
				scenario := model.Scenario{Src: source, Dst: target, Protocol: protocol, Port: port}
				if err := validateScenario(scenario); err != nil {
					return nil, err
				}
				results = append(results, Reachability(rules, scenario, e.DefaultAction))
			}
		}
	}
	return map[string]any{"total": len(results), "results": results}, nil
}
func stringList(params map[string]any, key string) ([]string, error) {
	values, ok := params[key].([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", key)
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("%s must contain strings", key)
		}
		out = append(out, text)
	}
	return out, nil
}
func intList(params map[string]any, key string) ([]int, error) {
	values, ok := params[key].([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", key)
	}
	out := make([]int, 0, len(values))
	for _, value := range values {
		number, ok := value.(float64)
		if !ok {
			return nil, fmt.Errorf("%s must contain numbers", key)
		}
		out = append(out, int(number))
	}
	return out, nil
}

func validateScenario(s model.Scenario) error {
	if !validAddress(s.Src) || !validAddress(s.Dst) {
		return fmt.Errorf("scenario src and dst must be IP or CIDR")
	}
	switch s.Protocol {
	case "tcp", "udp", "icmp", "any":
	default:
		return fmt.Errorf("invalid scenario protocol")
	}
	if s.Port < 1 || s.Port > 65535 {
		return fmt.Errorf("scenario port must be between 1 and 65535")
	}
	return nil
}
func validAddress(value string) bool {
	return net.ParseIP(value) != nil || func() bool { _, err := model.CIDR(value); return err == nil }()
}
