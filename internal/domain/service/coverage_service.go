package service

import (
	"net"
	"netpolicy/internal/domain/model"
)

func Coverage(rules []model.Rule, targets []string, defaultAction string) model.CoverageResult {
	if len(targets) == 0 {
		for _, r := range rules {
			targets = append(targets, r.Dst)
		}
	}
	covered := 0
	total := 0
	uncovered := []string{}
	for _, target := range targets {
		n, e := model.CIDR(target)
		if e != nil {
			continue
		}
		total += ipCount(n)
		hit := false
		for _, r := range rules {
			relation := model.AddressRelation(r.Dst, target)
			if relation == "equal" || relation == "contains" {
				hit = true
				break
			}
		}
		if hit {
			covered += ipCount(n)
		} else {
			uncovered = append(uncovered, target)
		}
	}
	ratio := 0.0
	if total > 0 {
		ratio = float64(covered) / float64(total)
		if ratio > 1 {
			ratio = 1
		}
	}
	counts := map[string]int{}
	for _, r := range rules {
		counts[r.PolicySet]++
	}
	per := map[string]float64{}
	for k := range counts {
		per[k] = ratio
	}
	return model.CoverageResult{CoverageRatio: ratio, TotalSpace: join(targets), CoveredSpace: covered, Uncovered: uncovered, PerPolicySet: per, DefaultAction: defaultAction}
}
func ipCount(n *net.IPNet) int {
	ones, bits := n.Mask.Size()
	if bits-ones > 8 {
		return 1
	}
	return 1 << (bits - ones)
}
func join(a []string) string {
	if len(a) == 0 {
		return ""
	}
	s := a[0]
	if len(a) > 1 {
		s += " 等"
	}
	return s
}
