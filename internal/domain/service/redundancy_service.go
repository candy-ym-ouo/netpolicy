package service

import "netpolicy/internal/domain/model"

func Redundancy(rules []model.Rule) []model.Redundancy {
	out := []model.Redundancy{}
	for i := range rules {
		for j := range rules {
			if i == j || rules[i].Action != rules[j].Action || rules[i].PolicySet != rules[j].PolicySet {
				continue
			}
			rel := model.ConditionRelation(rules[i], rules[j])
			if rel == "equal" {
				if rules[j].ID < rules[i].ID {
					out = append(out, model.Redundancy{RuleID: rules[i].ID, Against: rules[j].ID, Type: "repeat", SafeToDelete: true})
				}
			} else if (rel == "contained" || rel == "contains") && rules[j].Priority < rules[i].Priority {
				out = append(out, model.Redundancy{RuleID: rules[i].ID, Against: rules[j].ID, Type: "shadowed", SafeToDelete: true})
			}
		}
	}
	return out
}
