package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"netpolicy/internal/check"
	"netpolicy/internal/domain/model"
	"netpolicy/internal/parser"
	"strconv"
	"strings"
	"time"
)

type response struct {
	OK    bool `json:"ok"`
	Data  any  `json:"data,omitempty"`
	Error any  `json:"error,omitempty"`
}

func write(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(response{true, data, nil})
}
func fail(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(response{false, nil, map[string]string{"code": code, "message": msg}})
}

type importRequest struct {
	Format string `json:"format"`
	Mode   string `json:"mode"`
	Data   string `json:"data"`
}
type analysisRequest struct {
	PolicySets []string       `json:"policySets"`
	RuleIDs    []string       `json:"ruleIds"`
	Params     map[string]any `json:"params"`
}

func (s *Server) route(w http.ResponseWriter, r *http.Request, path string) {
	switch {
	case path == "/health":
		write(w, 200, map[string]any{"status": "ok", "store": "ready", "rulesetVersion": s.Repo.RulesetVersion()})
	case path == "/stats" && r.Method == "GET":
		s.stats(w)
	case path == "/rules/import" && r.Method == "POST":
		s.importRules(w, r)
	case path == "/rules" && r.Method == "GET":
		s.listRules(w, r)
	case path == "/rules/export" && r.Method == "GET":
		s.exportRules(w)
	case strings.HasPrefix(path, "/rules/") && r.Method == "DELETE":
		s.deleteRule(w, r, strings.TrimPrefix(path, "/rules/"))
	case strings.HasPrefix(path, "/rules/") && r.Method == "GET":
		s.getRule(w, strings.TrimPrefix(path, "/rules/"))
	case path == "/audit":
		a, _ := s.Repo.ListAuditLogs(50)
		write(w, 200, a)
	case path == "/checks":
		write(w, 200, check.Checker{Repo: s.Repo}.Run())
	case path == "/checks/latest":
		if x, ok := s.Repo.LatestReport(); ok {
			write(w, 200, x)
		} else {
			fail(w, 404, "NOT_FOUND", "no report")
		}
	case strings.HasPrefix(path, "/analysis/tasks/") && strings.HasSuffix(path, "/retry") && r.Method == "POST":
		s.retryTask(w, strings.TrimSuffix(strings.TrimPrefix(path, "/analysis/tasks/"), "/retry"))
	case strings.HasPrefix(path, "/analysis/tasks/") && r.Method == "GET":
		s.getTask(w, strings.TrimPrefix(path, "/analysis/tasks/"))
	case path == "/analysis/tasks" && r.Method == "GET":
		x, _ := s.Repo.ListTasks()
		write(w, 200, x)
	case path == "/analysis/tasks" && r.Method == "POST":
		s.createTask(w, r)
	case strings.HasPrefix(path, "/analysis/results/") && r.Method == "GET":
		s.getResult(w, strings.TrimPrefix(path, "/analysis/results/"))
	case strings.HasPrefix(path, "/analysis/") && r.Method == "POST":
		s.analyze(w, r, strings.TrimPrefix(path, "/analysis/"))
	case path == "/migrate/export":
		b, e := s.Repo.Export()
		if e != nil {
			fail(w, 500, "INTERNAL", e.Error())
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
		}
	case path == "/migrate/import" && r.Method == "POST":
		b, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			fail(w, 400, "BAD_REQUEST", readErr.Error())
			return
		}
		if e := s.Repo.Import(b); e != nil {
			fail(w, 400, "BAD_REQUEST", e.Error())
		} else {
			write(w, 200, map[string]bool{"imported": true})
		}
	default:
		fail(w, 404, "NOT_FOUND", "endpoint not found")
	}
}
func (s *Server) importRules(w http.ResponseWriter, r *http.Request) {
	var q importRequest
	if json.NewDecoder(r.Body).Decode(&q) != nil {
		fail(w, 400, "BAD_REQUEST", "invalid request")
		return
	}
	rs, errs := parser.Parse(q.Format, q.Data)
	if len(errs) > 0 {
		write(w, 400, map[string]any{"imported": 0, "errors": errs})
		return
	}
	var e error
	if q.Mode == "replace" {
		e = s.Repo.ReplaceAllRules(rs)
	} else {
		e = s.Repo.SaveRules(rs)
	}
	if e != nil {
		fail(w, 409, "CONFLICT", e.Error())
		return
	}
	_ = s.Repo.AppendAuditLog(model.AuditLog{User: r.Header.Get("X-User"), Action: "import", Target: "rules", Detail: fmt.Sprintf("%d rules", len(rs))})
	write(w, 200, map[string]any{"imported": len(rs), "rulesetVersion": s.Repo.RulesetVersion()})
}
func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	size, _ := strconv.Atoi(r.URL.Query().Get("pageSize"))
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 50
	}
	if size > 500 {
		size = 500
	}
	all, _ := s.Repo.ListRules(model.RuleFilter{PolicySet: r.URL.Query().Get("policySet"), Action: r.URL.Query().Get("action"), Query: r.URL.Query().Get("q")})
	start := (page - 1) * size
	if start > len(all) {
		start = len(all)
	}
	end := start + size
	if end > len(all) {
		end = len(all)
	}
	write(w, 200, map[string]any{"total": len(all), "page": page, "pageSize": size, "items": all[start:end]})
}
func (s *Server) stats(w http.ResponseWriter) {
	rules, _ := s.Repo.ListRules(model.RuleFilter{})
	tasks, _ := s.Repo.ListTasks()
	status := map[string]int{}
	policies := map[string]bool{}
	for _, rule := range rules {
		policies[rule.PolicySet] = true
	}
	for _, task := range tasks {
		status[task.Status]++
	}
	write(w, 200, map[string]any{"ruleCount": len(rules), "policySetCount": len(policies), "taskCount": len(tasks), "tasksByStatus": status, "rulesetVersion": s.Repo.RulesetVersion()})
}
func (s *Server) exportRules(w http.ResponseWriter) {
	rules, err := s.Repo.ListRules(model.RuleFilter{})
	if err != nil {
		fail(w, 500, "INTERNAL", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rules)
}
func (s *Server) getRule(w http.ResponseWriter, id string) {
	if r, ok := s.Repo.GetRule(id); ok {
		write(w, 200, r)
	} else {
		fail(w, 404, "RULE_NOT_FOUND", "rule not found")
	}
}
func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request, id string) {
	if e := s.Repo.DeleteRule(id); e != nil {
		fail(w, 404, "RULE_NOT_FOUND", e.Error())
	} else {
		write(w, 200, map[string]any{"deleted": true, "rulesetVersion": s.Repo.RulesetVersion()})
	}
}
func (s *Server) analyze(w http.ResponseWriter, r *http.Request, kind string) {
	var q analysisRequest
	if json.NewDecoder(r.Body).Decode(&q) != nil {
		fail(w, 400, "BAD_REQUEST", "invalid request")
		return
	}
	rules, _ := s.Repo.ListRules(model.RuleFilter{})
	if len(q.PolicySets) > 0 || len(q.RuleIDs) > 0 {
		rules = selectRules(rules, q.PolicySets, q.RuleIDs)
	}
	v, e := s.Engine.Analyze(kind, rules, q.Params)
	if e != nil {
		fail(w, 400, "BAD_REQUEST", e.Error())
		return
	}
	write(w, 200, v)
}
func (s *Server) createTask(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Type       string         `json:"type"`
		PolicySets []string       `json:"policySets"`
		RuleIDs    []string       `json:"ruleIds"`
		Params     map[string]any `json:"params"`
	}
	if json.NewDecoder(r.Body).Decode(&q) != nil || q.Type == "" {
		fail(w, 400, "BAD_REQUEST", "type required")
		return
	}
	if q.Type != "coverage" && q.Type != "conflicts" && q.Type != "redundancy" && q.Type != "reachability" && q.Type != "matrix" {
		fail(w, 400, "BAD_REQUEST", "unsupported analysis type")
		return
	}
	id := fmt.Sprintf("t_%d", time.Now().UnixNano())
	t := &model.AnalysisTask{ID: id, Type: q.Type, Status: "pending", RulesetVersion: s.Repo.RulesetVersion(), CreatedAt: time.Now().UTC()}
	if q.Params == nil {
		q.Params = map[string]any{}
	}
	q.Params["_policySets"] = q.PolicySets
	q.Params["_ruleIds"] = q.RuleIDs
	b, _ := json.Marshal(q.Params)
	t.Params = string(b)
	if err := s.Repo.CreateTask(t); err != nil {
		fail(w, 500, "INTERNAL", err.Error())
		return
	}
	s.Workers.EnqueueContext(context.Background(), id)
	write(w, 202, map[string]string{"taskId": id, "status": "pending"})
}
func selectRules(rules []model.Rule, policySets, ruleIDs []string) []model.Rule {
	policies := map[string]bool{}
	ids := map[string]bool{}
	for _, value := range policySets {
		policies[value] = true
	}
	for _, value := range ruleIDs {
		ids[value] = true
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
func (s *Server) retryTask(w http.ResponseWriter, id string) {
	task, ok := s.Repo.GetTask(id)
	if !ok {
		fail(w, 404, "TASK_NOT_FOUND", "task not found")
		return
	}
	if task.Status != "failed" {
		fail(w, 409, "CONFLICT", "only failed tasks can be retried")
		return
	}
	task.Status = "pending"
	task.Error = ""
	task.RetryCount++
	if err := s.Repo.UpdateTask(&task); err != nil {
		fail(w, 500, "INTERNAL", err.Error())
		return
	}
	s.Workers.Enqueue(id)
	write(w, 202, map[string]any{"taskId": id, "status": task.Status, "retryCount": task.RetryCount})
}
func (s *Server) getTask(w http.ResponseWriter, id string) {
	if t, ok := s.Repo.GetTask(id); ok {
		write(w, 200, t)
	} else {
		fail(w, 404, "TASK_NOT_FOUND", "task not found")
	}
}
func (s *Server) getResult(w http.ResponseWriter, id string) {
	if x, ok := s.Repo.GetResult(id); ok {
		write(w, 200, x)
	} else {
		fail(w, 404, "RESULT_NOT_FOUND", "result not found")
	}
}
