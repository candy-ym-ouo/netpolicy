package model

import "time"

type AnalysisTask struct {
	ID             string     `json:"id"`
	Type           string     `json:"type"`
	Status         string     `json:"status"`
	Params         string     `json:"params"`
	RulesetVersion int        `json:"rulesetVersion"`
	RetryCount     int        `json:"retryCount"`
	Error          string     `json:"error,omitempty"`
	CreatedAt      time.Time  `json:"createdAt"`
	StartedAt      *time.Time `json:"startedAt,omitempty"`
	FinishedAt     *time.Time `json:"finishedAt,omitempty"`
}
type AnalysisResult struct {
	TaskID         string    `json:"taskId"`
	Type           string    `json:"type"`
	RulesetVersion int       `json:"rulesetVersion"`
	Summary        string    `json:"summary"`
	Payload        string    `json:"payload"`
	CreatedAt      time.Time `json:"createdAt"`
}
type AuditLog struct {
	ID     int64     `json:"id"`
	At     time.Time `json:"at"`
	User   string    `json:"user"`
	Action string    `json:"action"`
	Target string    `json:"target"`
	Detail string    `json:"detail"`
}
type CheckItem struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	Level    string `json:"level"`
	Detail   string `json:"detail"`
}
type CheckReport struct {
	RunAt    time.Time   `json:"runAt"`
	Passed   int         `json:"passed"`
	Warnings int         `json:"warnings"`
	Failed   int         `json:"failed"`
	Items    []CheckItem `json:"items"`
}
type Scenario struct {
	Src      string `json:"src"`
	Dst      string `json:"dst"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}
type ReachabilityResult struct {
	Scenario      Scenario      `json:"scenario"`
	Verdict       string        `json:"verdict"`
	DefaultAction string        `json:"defaultAction"`
	MatchedChain  []MatchedRule `json:"matchedChain"`
}
type MatchedRule struct {
	RuleID   string `json:"ruleId"`
	Priority int    `json:"priority"`
	Action   string `json:"action"`
	Reason   string `json:"reason"`
}
type Conflict struct {
	RuleA      string `json:"ruleA"`
	RuleB      string `json:"ruleB"`
	Level      string `json:"level"`
	Relation   string `json:"relation"`
	Suggestion string `json:"suggestion"`
}
type Redundancy struct {
	RuleID       string `json:"ruleId"`
	Against      string `json:"against"`
	Type         string `json:"type"`
	SafeToDelete bool   `json:"safeToDelete"`
}
type CoverageResult struct {
	CoverageRatio  float64            `json:"coverageRatio"`
	TotalSpace     string             `json:"totalSpace"`
	CoveredSpace   int                `json:"coveredSpace"`
	Uncovered      []string           `json:"uncovered"`
	RedundantRatio float64            `json:"redundantRatio"`
	PerPolicySet   map[string]float64 `json:"perPolicySet"`
	DefaultAction  string             `json:"defaultAction"`
}
