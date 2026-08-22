package api

import (
	"net/http"
	"strings"
)

func register(m *http.ServeMux, s *Server) {
	m.HandleFunc("/api/v1/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/v1")
		s.route(w, r, path)
	})
}
