package storage_test

import (
	"errors"
	"netpolicy/internal/storage"
	"testing"
)

func TestBug02_DeleteMissingRuleMustMatchErrNotFound(t *testing.T) {
	store := storage.NewMemory("")
	err := store.DeleteRule("missing-rule")
	if err == nil {
		t.Fatal("expected an error when deleting a missing rule")
	}
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("errors.Is(err, storage.ErrNotFound) = false, err = %v", err)
	}
}
