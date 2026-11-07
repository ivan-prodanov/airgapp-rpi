package handlers

import (
	"encoding/json"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"path/filepath"
	"sync"
)

type Renderer struct {
	tmplFS fs.FS
	mu     sync.RWMutex // guards cache: pages are parsed lazily on first request, possibly concurrently
	cache  map[string]*template.Template
}

func NewRenderer(tmplFS fs.FS) *Renderer {
	return &Renderer{
		tmplFS: tmplFS,
		cache:  make(map[string]*template.Template),
	}
}

func (r *Renderer) RenderPage(w http.ResponseWriter, name string, data any) {
	r.mu.RLock()
	tmpl, ok := r.cache[name]
	r.mu.RUnlock()
	if !ok {
		r.mu.Lock()
		tmpl, ok = r.cache[name]
		if !ok {
			var err error
			tmpl, err = template.ParseFS(r.tmplFS,
				filepath.Join("templates", "layout.html"),
				filepath.Join("templates", name),
			)
			if err != nil {
				r.mu.Unlock()
				log.Printf("[ERROR] Failed to parse template %s: %v", name, err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			r.cache[name] = tmpl
		}
		r.mu.Unlock()
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		log.Printf("[ERROR] Failed to render template %s: %v", name, err)
	}
}

func (r *Renderer) RenderLogin(w http.ResponseWriter, data any) {
	tmpl, err := template.ParseFS(r.tmplFS, filepath.Join("templates", "login.html"))
	if err != nil {
		log.Printf("[ERROR] Failed to parse login template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, data)
}

func JSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func JSONError(w http.ResponseWriter, status int, msg string) {
	JSON(w, status, map[string]string{"error": msg})
}
