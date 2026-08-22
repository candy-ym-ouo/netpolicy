package service

import "netpolicy/internal/domain/model"

func Conflicts(rules []model.Rule) []model.Conflict {
	out := []model.Conflict{}
	for i := 0; i < len(rules); i++ {
		for j := i + 1; j < len(rules); j++ {
			a, b := rules[i], rules[j]
			if a.PolicySet != b.PolicySet || a.Action == b.Action || !model.ConditionsOverlap(a, b) {
				continue
			}
			rel := model.ConditionRelation(a, b)
			level := "HIGH"
			if rel == "equal" {
				level = "CRITICAL"
			}
			if rel == "contains" || rel == "contained" {
				level = "MEDIUM"
			}
			out = append(out, model.Conflict{RuleA: a.ID, RuleB: b.ID, Level: level, Relation: rel, Suggestion: "调整动作或拆分重叠条件"})
		}
	}
	return out
}
