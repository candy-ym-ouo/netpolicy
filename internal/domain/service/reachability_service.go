package service

import (
	"netpolicy/internal/domain/model"
	"sort"
)

func Reachability(rules []model.Rule, s model.Scenario, defaultAction string) model.ReachabilityResult {
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority == rules[j].Priority {
			return rules[i].ID < rules[j].ID
		}
		return rules[i].Priority < rules[j].Priority
	})
	chain := []model.MatchedRule{}
	verdict := defaultAction
	for _, r := range rules {
		if !model.IPIn(r.Src, s.Src) || !model.IPIn(r.Dst, s.Dst) || !model.ProtocolOverlap(r.Protocol, s.Protocol) || ((r.Protocol == "tcp" || r.Protocol == "udp" || r.Protocol == "any") && (s.Port < r.PortFrom || s.Port > r.PortTo)) {
			continue
		}
		chain = append(chain, model.MatchedRule{RuleID: r.ID, Priority: r.Priority, Action: r.Action, Reason: "source, destination, protocol and port matched"})
		if len(chain) == 1 {
			verdict = r.Action
		}
	}
	return model.ReachabilityResult{Scenario: s, Verdict: verdict, DefaultAction: defaultAction, MatchedChain: chain}
}
