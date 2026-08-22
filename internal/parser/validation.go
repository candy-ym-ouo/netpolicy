package parser

import (
	"fmt"
	"net"
	"netpolicy/internal/domain/model"
)

type ValidationError struct {
	Line    int    `json:"line"`
	Field   string `json:"field"`
	Message string `json:"message"`
}

func Validate(r model.Rule, line int) error {
	if r.ID == "" {
		return fmt.Errorf("line %d id is required", line)
	}
	for _, v := range []struct{ n, s string }{{"src", r.Src}, {"dst", r.Dst}} {
		if _, _, e := net.ParseCIDR(v.s); e != nil {
			return fmt.Errorf("line %d %s: invalid CIDR", line, v.n)
		}
	}
	if r.Action != "allow" && r.Action != "deny" {
		return fmt.Errorf("line %d action must be allow or deny", line)
	}
	if r.Priority < 1 || r.PortFrom < 1 || r.PortTo > 65535 || r.PortFrom > r.PortTo {
		return fmt.Errorf("line %d invalid priority or port range", line)
	}
	switch r.Protocol {
	case "tcp", "udp", "icmp", "any":
	default:
		return fmt.Errorf("line %d invalid protocol", line)
	}
	return nil
}
