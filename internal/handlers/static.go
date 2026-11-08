package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"sync"
)

// StaticHandler serves the embedded static files with caching that suits
// them. The embedded files carry no modification time, so without this the
// browser re-downloaded everything on every page, fonts included, and the
// menu re-flowed when Martian Mono arrived a frame late.
//
//   - Fonts are kept for a year: they never change under the same name.
//   - Everything else (CSS, JS, images) revalidates against a content-hash
//     ETag: a new build is picked up at once, an unchanged file costs a 304.
func StaticHandler(staticFS fs.FS) http.Handler {
	files := http.FileServer(http.FS(staticFS))
	var mu sync.Mutex
	etags := map[string]string{}
	etagFor := func(name string) string {
		mu.Lock()
		defer mu.Unlock()
		if e, ok := etags[name]; ok {
			return e
		}
		b, err := fs.ReadFile(staticFS, name)
		if err != nil {
			return ""
		}
		sum := sha256.Sum256(b)
		e := `"` + hex.EncodeToString(sum[:8]) + `"`
		etags[name] = e
		return e
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		switch path.Ext(name) {
		case ".woff2", ".woff":
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		default:
			if e := etagFor(name); e != "" {
				w.Header().Set("ETag", e) // http.FileServer answers If-None-Match with 304
				w.Header().Set("Cache-Control", "no-cache")
			}
		}
		files.ServeHTTP(w, r)
	})
}
