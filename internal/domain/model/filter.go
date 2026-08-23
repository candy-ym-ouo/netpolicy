package model

// FilterRules narrows rules to those matching the requested scope. A rule is
// kept only when it satisfies every specified filter: it must belong to one of
// policySets (when that list is non-empty) and its ID must be in ruleIDs (when
// that list is non-empty). With both lists empty all rules are returned. This
// is the single source of truth for the policySets/ruleIds intersection used by
// both the synchronous analysis handler and the asynchronous worker, so the two
// paths cannot drift apart.
func FilterRules(rules []Rule, policySets, ruleIDs []string) []Rule {
	policies := map[string]bool{}
	ids := map[string]bool{}
	for _, value := range policySets {
		policies[value] = true
	}
	for _, value := range ruleIDs {
		ids[value] = true
	}
	if len(policies) == 0 && len(ids) == 0 {
		return rules
	}
	out := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		if len(policies) > 0 && !policies[rule.PolicySet] {
			continue
		}
		if len(ids) > 0 && !ids[rule.ID] {
			continue
		}
		out = append(out, rule)
	}
	return out
}
