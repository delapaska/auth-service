package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/delapaska/auth-service/database"
	"github.com/delapaska/auth-service/handlers"
	"github.com/gorilla/mux"
)

func main() {
	if err := database.InitMongoDB(); err != nil {
		log.Fatal("Error connecting to MongoDB:", err)
		return
	}

	router := mux.NewRouter()
	router.HandleFunc("/generate-tokens", handlers.GenerateTokensHandler).Methods("GET")
	router.HandleFunc("/refresh-tokens", handlers.RefreshTokensHandler).Methods("GET")

	http.Handle("/", router)

	fmt.Println("Server is running on :8080")
	http.ListenAndServe(":8080", nil)
}
