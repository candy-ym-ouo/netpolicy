package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"netpolicy/internal/domain/model"
	"netpolicy/internal/domain/service"
	"netpolicy/internal/storage"
	"sync"
	"time"
)

type Manager struct {
	repo   storage.Repository
	engine service.Engine
	queue  chan string
	done   chan struct{}
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func New(repo storage.Repository, engine service.Engine, n int) *Manager {
	if n < 1 {
		n = 1
	}
	m := &Manager{repo: repo, engine: engine, queue: make(chan string, n*2), done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	for i := 0; i < n; i++ {
		m.wg.Add(1)
		go m.run(ctx)
	}
	return m
}
func (m *Manager) Enqueue(id string) {
	select {
	case m.queue <- id:
	case <-m.done:
	}
}
func (m *Manager) EnqueueContext(ctx context.Context, id string) {
	select {
	case m.queue <- id:
	case <-m.done:
	case <-ctx.Done():
	}
}
func (m *Manager) run(ctx context.Context) {
	defer m.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-m.queue:
			m.execute(id)
		}
	}
}
func (m *Manager) execute(id string) {
	ok, _ := m.repo.CASStatus(id, "pending", "running")
	if !ok {
		return
	}
	t, ok := m.repo.GetTask(id)
	if !ok {
		return
	}
	var params map[string]any
	_ = json.Unmarshal([]byte(t.Params), &params)
	rules, _ := m.repo.ListRules(model.RuleFilter{})
	rules = selectRules(rules, params)
	value, err := m.engine.Analyze(t.Type, rules, params)
	if err == nil {
		payload, _ := json.Marshal(value)
		err = m.repo.SaveResult(&model.AnalysisResult{TaskID: id, Type: t.Type, RulesetVersion: t.RulesetVersion, Summary: "analysis completed", Payload: string(payload), CreatedAt: time.Now().UTC()})
	}
	if err != nil {
		t.Status = "failed"
		t.Error = err.Error()
	} else {
		t.Status = "success"
	}
	now := time.Now().UTC()
	t.FinishedAt = &now
	_ = m.repo.UpdateTask(&t)
}
func selectRules(rules []model.Rule, params map[string]any) []model.Rule {
	policies := map[string]bool{}
	ids := map[string]bool{}
	if values, ok := params["_policySets"].([]any); ok {
		for _, value := range values {
			if text, ok := value.(string); ok {
				policies[text] = true
			}
		}
	}
	if values, ok := params["_ruleIds"].([]any); ok {
		for _, value := range values {
			if text, ok := value.(string); ok {
				ids[text] = true
			}
		}
	}
	if len(policies) == 0 && len(ids) == 0 {
		return rules
	}
	out := make([]model.Rule, 0, len(rules))
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
func (m *Manager) Close() { close(m.done); m.cancel(); m.wg.Wait() }

var _ = fmt.Sprint
