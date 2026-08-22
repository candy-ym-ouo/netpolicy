package api

import (
	"net/http"
	"netpolicy/internal/domain/service"
	"netpolicy/internal/storage"
	"netpolicy/internal/worker"
	"os"
	"path/filepath"
)

type Server struct {
	Repo    storage.Repository
	Engine  service.Engine
	Workers *worker.Manager
	Addr    string
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	register(mux, s)
	mux.Handle("/", staticFiles())
	return logging(mux)
}
func staticFiles() http.Handler {
	root := filepath.Clean("web")
	if executable, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(executable), "web")
		if _, err := os.Stat(candidate); err == nil {
			root = candidate
		}
	}
	if _, err := os.Stat(root); err != nil {
		root = filepath.Clean("web")
	}
	return http.FileServer(http.Dir(root))
}
func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}
