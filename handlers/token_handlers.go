package handlers

import (
	"context"
	"fmt"
	"net/http"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"

	"github.com/delapaska/auth-service/config"
	"github.com/delapaska/auth-service/database"
	"github.com/delapaska/auth-service/models"
)

func GenerateTokensHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")

	access, refresh, err := models.GenerateTokens(userID)
	if err != nil {
		http.Error(w, "Error generating tokens", http.StatusInternalServerError)
		return
	}

	hashedRefresh, err := bcrypt.GenerateFromPassword([]byte(refresh), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing refresh token", http.StatusInternalServerError)
		return
	}

	// Сохранение или обновление токенов в БД
	collection := database.Client.Database(config.DbName).Collection(config.CollectionName)
	_, err = collection.UpdateOne(
		context.Background(),
		bson.M{"user_id": userID},
		bson.M{"$set": bson.M{"refresh_token": string(hashedRefresh)}},
		options.Update().SetUpsert(true),
	)
	if err != nil {
		http.Error(w, "Error saving tokens to DB", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Access Token: %s\nRefresh Token: %s\n", access, refresh)
}

func RefreshTokensHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	refreshRequest := r.URL.Query().Get("refresh_token")

	collection := database.Client.Database(config.DbName).Collection(config.CollectionName)
	var token models.Token
	err := collection.FindOne(context.Background(), bson.M{"user_id": userID}).Decode(&token)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(token.RefreshToken), []byte(refreshRequest))
	if err != nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	access, refresh, err := models.GenerateTokens(userID)
	if err != nil {
		http.Error(w, "Error generating tokens", http.StatusInternalServerError)
		return
	}

	hashedRefresh, err := bcrypt.GenerateFromPassword([]byte(refresh), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing refresh token", http.StatusInternalServerError)
		return
	}

	_, err = collection.UpdateOne(
		context.Background(),
		bson.M{"user_id": userID, "refresh_token": token.RefreshToken},
		bson.M{"$set": bson.M{"refresh_token": string(hashedRefresh)}},
	)
	if err != nil {
		http.Error(w, "Error updating tokens in DB", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "New Access Token: %s\nNew Refresh Token: %s\n", access, refresh)
}
