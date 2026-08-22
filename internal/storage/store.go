package storage

import (
	"encoding/json"
	"netpolicy/internal/domain/model"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type dump struct {
	Rules   []model.Rule           `json:"rules"`
	Tasks   []model.AnalysisTask   `json:"tasks"`
	Results []model.AnalysisResult `json:"results"`
	Audit   []model.AuditLog       `json:"audit"`
	Version int                    `json:"rulesetVersion"`
	Report  *model.CheckReport     `json:"report,omitempty"`
}
type MemoryStore struct {
	mu        sync.RWMutex
	rules     map[string]model.Rule
	tasks     map[string]model.AnalysisTask
	results   map[string]model.AnalysisResult
	audit     []model.AuditLog
	version   int
	nextAudit int64
	report    *model.CheckReport
	path      string
}

func NewMemory(path string) *MemoryStore {
	return &MemoryStore{rules: map[string]model.Rule{}, tasks: map[string]model.AnalysisTask{}, results: map[string]model.AnalysisResult{}, path: path}
}
func (s *MemoryStore) SaveRules(rs []model.Rule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := make(map[string]bool, len(rs))
	for _, r := range rs {
		if seen[r.ID] {
			return ErrConflict
		}
		seen[r.ID] = true
		if _, ok := s.rules[r.ID]; ok {
			return ErrConflict
		}
	}
	for _, r := range rs {
		s.rules[r.ID] = r
	}
	s.version++
	if err := s.persist(); err != nil {
		for _, r := range rs {
			delete(s.rules, r.ID)
		}
		s.version--
		return err
	}
	return nil
}
func (s *MemoryStore) ReplaceAllRules(rs []model.Rule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := make(map[string]bool, len(rs))
	for _, r := range rs {
		if seen[r.ID] {
			return ErrConflict
		}
		seen[r.ID] = true
	}
	previous := s.rules
	previousVersion := s.version
	s.rules = map[string]model.Rule{}
	for _, r := range rs {
		s.rules[r.ID] = r
	}
	s.version++
	if err := s.persist(); err != nil {
		s.rules = previous
		s.version = previousVersion
		return err
	}
	return nil
}
func (s *MemoryStore) ListRules(f model.RuleFilter) ([]model.Rule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []model.Rule{}
	for _, r := range s.rules {
		if f.PolicySet != "" && r.PolicySet != f.PolicySet || f.Action != "" && r.Action != f.Action || f.Query != "" && !contains(r.ID, f.Query) && !contains(r.Description, f.Query) {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out, nil
}
func contains(a, b string) bool {
	for i := 0; i+len(b) <= len(a); i++ {
		if a[i:i+len(b)] == b {
			return true
		}
	}
	return false
}
func (s *MemoryStore) GetRule(id string) (model.Rule, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.rules[id]
	return r, ok
}
func (s *MemoryStore) DeleteRule(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rules[id]
	if !ok {
		return ErrNotFound
	}
	delete(s.rules, id)
	s.version++
	if err := s.persist(); err != nil {
		s.rules[id] = r
		s.version--
		return err
	}
	return nil
}
func (s *MemoryStore) RulesetVersion() int { return s.version }
func (s *MemoryStore) CreateTask(t *model.AnalysisTask) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.tasks[t.ID]; exists {
		return ErrConflict
	}
	s.tasks[t.ID] = *t
	if err := s.persist(); err != nil {
		delete(s.tasks, t.ID)
		return err
	}
	return nil
}
func (s *MemoryStore) UpdateTask(t *model.AnalysisTask) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, exists := s.tasks[t.ID]
	if !exists {
		return ErrNotFound
	}
	if !validTaskTransition(previous.Status, t.Status) {
		return ErrConflict
	}
	s.tasks[t.ID] = *t
	if err := s.persist(); err != nil {
		s.tasks[t.ID] = previous
		return err
	}
	return nil
}
func validTaskTransition(from, to string) bool {
	if from == to {
		return true
	}
	switch from {
	case "pending":
		return to == "running" || to == "canceled"
	case "running":
		return to == "success" || to == "failed" || to == "canceled"
	case "failed":
		return to == "pending"
	default:
		return false
	}
}
func (s *MemoryStore) GetTask(id string) (model.AnalysisTask, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tasks[id]
	return t, ok
}
func (s *MemoryStore) ListTasks() ([]model.AnalysisTask, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a := []model.AnalysisTask{}
	for _, t := range s.tasks {
		a = append(a, t)
	}
	sort.Slice(a, func(i, j int) bool { return a[i].CreatedAt.After(a[j].CreatedAt) })
	return a, nil
}
func (s *MemoryStore) CASStatus(id, from, to string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[id]
	if !ok {
		return false, ErrNotFound
	}
	if t.Status != from {
		return false, nil
	}
	previous := t
	t.Status = to
	now := modelTime()
	if to == "running" {
		t.StartedAt = &now
	}
	s.tasks[id] = t
	if err := s.persist(); err != nil {
		s.tasks[id] = previous
		return false, err
	}
	return true, nil
}
func modelTime() (t time.Time) { return time.Now().UTC() }
func (s *MemoryStore) SaveResult(r *model.AnalysisResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, exists := s.results[r.TaskID]
	s.results[r.TaskID] = *r
	if err := s.persist(); err != nil {
		if exists {
			s.results[r.TaskID] = previous
		} else {
			delete(s.results, r.TaskID)
		}
		return err
	}
	return nil
}
func (s *MemoryStore) GetResult(id string) (model.AnalysisResult, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.results[id]
	return r, ok
}
func (s *MemoryStore) ListResults() ([]model.AnalysisResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a := []model.AnalysisResult{}
	for _, r := range s.results {
		a = append(a, r)
	}
	return a, nil
}
func (s *MemoryStore) AppendAuditLog(a model.AuditLog) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextAudit++
	a.ID = s.nextAudit
	if a.At.IsZero() {
		a.At = modelTime()
	}
	s.audit = append(s.audit, a)
	return s.persist()
}
func (s *MemoryStore) ListAuditLogs(limit int) ([]model.AuditLog, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > len(s.audit) {
		limit = len(s.audit)
	}
	out := make([]model.AuditLog, 0, limit)
	for i := len(s.audit) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, s.audit[i])
	}
	return out, nil
}
func (s *MemoryStore) SetReport(r model.CheckReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.report = &r
	_ = s.persist()
}
func (s *MemoryStore) LatestReport() (model.CheckReport, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.report == nil {
		return model.CheckReport{}, false
	}
	return *s.report, true
}
func (s *MemoryStore) Export() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rs := []model.Rule{}
	for _, r := range s.rules {
		rs = append(rs, r)
	}
	ts := []model.AnalysisTask{}
	for _, t := range s.tasks {
		ts = append(ts, t)
	}
	zs := []model.AnalysisResult{}
	for _, r := range s.results {
		zs = append(zs, r)
	}
	return json.Marshal(dump{rs, ts, zs, s.audit, s.version, s.report})
}
func (s *MemoryStore) Import(data []byte) error {
	var d dump
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = map[string]model.Rule{}
	for _, r := range d.Rules {
		s.rules[r.ID] = r
	}
	s.tasks = map[string]model.AnalysisTask{}
	for _, t := range d.Tasks {
		s.tasks[t.ID] = t
	}
	s.results = map[string]model.AnalysisResult{}
	for _, r := range d.Results {
		s.results[r.TaskID] = r
	}
	s.audit = d.Audit
	s.nextAudit = 0
	for _, entry := range s.audit {
		if entry.ID > s.nextAudit {
			s.nextAudit = entry.ID
		}
	}
	s.version = d.Version
	s.report = d.Report
	return s.persistLocked()
}
func (s *MemoryStore) persist() error {
	if s.path == "" {
		return nil
	}
	return s.persistLocked()
}
func (s *MemoryStore) persistLocked() error {
	data, err := s.ExportUnlocked()
	if err != nil {
		return err
	}
	directory := filepath.Dir(s.path)
	temporary, err := os.CreateTemp(directory, ".netpolicy-*.tmp")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, s.path)
}
func (s *MemoryStore) ExportUnlocked() ([]byte, error) {
	rs := []model.Rule{}
	for _, r := range s.rules {
		rs = append(rs, r)
	}
	ts := []model.AnalysisTask{}
	for _, t := range s.tasks {
		ts = append(ts, t)
	}
	zs := []model.AnalysisResult{}
	for _, r := range s.results {
		zs = append(zs, r)
	}
	return json.Marshal(dump{rs, ts, zs, s.audit, s.version, s.report})
}
func (s *MemoryStore) Close() error { return nil }
