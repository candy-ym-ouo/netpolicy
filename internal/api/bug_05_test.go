package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"netpolicy/internal/domain/model"
	"netpolicy/internal/domain/service"
	"netpolicy/internal/storage"
	"netpolicy/internal/worker"
	"strings"
	"testing"
	"time"
)

func TestBug05_AsyncTaskRuleIdsFilterMustApply(t *testing.T) {
	repo := storage.NewMemory("")
	rules := []model.Rule{
		{ID: "r1", PolicySet: "p1", Priority: 2, Action: model.Deny, Src: "10.0.0.0/8", Dst: "10.1.0.0/16", Protocol: model.Any, PortFrom: 1, PortTo: 65535},
		{ID: "r2", PolicySet: "p1", Priority: 1, Action: model.Allow, Src: "10.0.0.0/8", Dst: "10.1.0.0/16", Protocol: model.Any, PortFrom: 1, PortTo: 65535},
	}
	if err := repo.SaveRules(rules); err != nil {
		t.Fatalf("save rules: %v", err)
	}
	engine := service.Engine{DefaultAction: model.DefaultDeny}
	wm := worker.New(repo, engine, 1)
	defer wm.Close()
	srv := &Server{Repo: repo, Engine: engine, Workers: wm}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/analysis/tasks", strings.NewReader(`{"type":"reachability","ruleIds":["r1"],"params":{"scenario":{"src":"10.0.0.1","dst":"10.1.0.1","protocol":"tcp","port":443}}}`))
	srv.route(rec, req, "/analysis/tasks")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d (%s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			TaskID string `json:"taskId"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Data.TaskID == "" {
		t.Fatal("missing taskId in response")
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		task, ok := repo.GetTask(resp.Data.TaskID)
		if ok {
			switch task.Status {
			case "success":
				result, ok := repo.GetResult(resp.Data.TaskID)
				if !ok {
					t.Fatal("missing analysis result")
				}
				var payload model.ReachabilityResult
				if err := json.Unmarshal([]byte(result.Payload), &payload); err != nil {
					t.Fatalf("decode analysis result: %v", err)
				}
				if payload.Verdict != model.Deny {
					t.Fatalf("expected policy p1 to produce deny, got %s", payload.Verdict)
				}
				return
			case "failed":
				t.Fatalf("task failed: %s", task.Error)
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("task did not finish in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
