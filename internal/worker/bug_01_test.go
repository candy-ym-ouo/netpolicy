package worker

import (
	"encoding/json"
	"netpolicy/internal/domain/service"
	"netpolicy/internal/storage"
	"path/filepath"
	"testing"
	"time"
)

func TestBug01_RestoredNullParamsMustNotPanic(t *testing.T) {
	store := storage.NewMemory(filepath.Join(t.TempDir(), "dump.json"))
	data, err := json.Marshal(map[string]any{
		"tasks": []any{
			map[string]any{
				"id":             "t_null",
				"type":           "conflicts",
				"status":         "pending",
				"params":         "null",
				"rulesetVersion": 0,
				"createdAt":      time.Now().UTC(),
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal dump: %v", err)
	}
	if err := store.Import(data); err != nil {
		t.Fatalf("import dump: %v", err)
	}
	m := New(store, service.Engine{}, 1)
	defer m.Close()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic while executing restored task: %v", r)
		}
	}()
	m.execute("t_null")
	task, ok := store.GetTask("t_null")
	if !ok {
		t.Fatal("task not found after execution")
	}
	if task.Status != "success" {
		t.Fatalf("expected task status success, got %s (error: %s)", task.Status, task.Error)
	}
}
