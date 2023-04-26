package main

import (
	"github.com/gazebo-web/auth/pkg/authentication"
	"github.com/gazebo-web/auth/pkg/middleware"
	"github.com/rs/cors"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	fp := os.Getenv("AUTHENTICATION_PUBLIC_KEY_FILE")
	f, err := os.ReadFile(fp)
	if err != nil {
		log.Fatalln("Failed to read file:", err)
	}
	auth := authentication.NewTokenAuthentication(f)
	bearer := middleware.BearerToken(auth)

	srv := http.Server{
		Addr:         ":3030",
		Handler:      cors.AllowAll().Handler(bearer(http.HandlerFunc(handler))),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  2 * time.Second,
	}
	log.Println("Listening on", srv.Addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalln("Failed to listen and serve:", err)
	}
	log.Println("Shutting server down...")
}

func handler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("Welcome!")); err != nil {
		http.Error(w, "Failed to render page", http.StatusInternalServerError)
	}
}
