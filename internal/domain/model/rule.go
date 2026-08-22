package model

import "time"

const (
	Allow       = "allow"
	Deny        = "deny"
	Any         = "any"
	DefaultDeny = "deny"
)

type Rule struct {
	ID          string    `json:"id"`
	PolicySet   string    `json:"policySet"`
	Priority    int       `json:"priority"`
	Action      string    `json:"action"`
	Src         string    `json:"src"`
	Dst         string    `json:"dst"`
	Protocol    string    `json:"protocol"`
	PortFrom    int       `json:"portFrom"`
	PortTo      int       `json:"portTo"`
	Description string    `json:"description"`
	Source      string    `json:"source"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type RuleFilter struct {
	PolicySet, Action, Query string
	Page, PageSize           int
}

func (r Rule) Normalize() Rule {
	if r.PolicySet == "" {
		r.PolicySet = "default"
	}
	if r.Priority == 0 {
		r.Priority = 100
	}
	if r.Protocol == "" {
		r.Protocol = Any
	}
	if r.PortFrom == 0 {
		r.PortFrom = 1
	}
	if r.PortTo == 0 {
		r.PortTo = 65535
	}
	now := time.Now().UTC()
	if r.CreatedAt.IsZero() {
		r.CreatedAt = now
	}
	r.UpdatedAt = now
	return r
}
