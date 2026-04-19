package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// securityHeaders middleware adds basic security protections
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		next.ServeHTTP(w, r)
	})
}

// custom file server that prevents directory traversal
func safeFileServer(root http.Dir) http.Handler {
	fs := http.FileServer(root)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Clean the path to prevent traversal
		cleanPath := filepath.Clean(r.URL.Path)

		// Force root to index.html
		if cleanPath == "/" {
			http.ServeFile(w, r, "static/index.html")
			return
		}

		// Build full path
		fullPath := filepath.Join(string(root), cleanPath)

		// Check if file exists
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			w.WriteHeader(http.StatusNotFound)
			http.ServeFile(w, r, "static/404.html")
			return
		}

		fs.ServeHTTP(w, r)
	})
}

func main() {
	mux := http.NewServeMux()

	// Serve static files securely
	fileHandler := safeFileServer(http.Dir("./static"))
	mux.Handle("/", securityHeaders(fileHandler))

	server := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	log.Println("Server running at http://localhost:8080")
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
