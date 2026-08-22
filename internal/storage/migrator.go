package storage

import (
	"netpolicy/internal/domain/model"
	"os"
)

type Migrator struct{ Version int }

func (m Migrator) Up(r Repository) error { m.Version = 1; return nil }
func (r *MemoryStore) Load(path string) error {
	data, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	return r.Import(data)
}

var _ = model.Allow
