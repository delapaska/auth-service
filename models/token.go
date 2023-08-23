package models

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/dgrijalva/jwt-go"

	"github.com/delapaska/auth-service/config"
)

type Token struct {
	UserID       string `bson:"user_id"`
	RefreshToken string `bson:"refresh_token"`
}

func GenerateTokens(userID string) (string, string, error) {
	// Генерация Access токена
	accessClaims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 1).Unix(), // Токен живет 1 час
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, accessClaims)
	accessSigned, err := accessToken.SignedString([]byte(config.SecretKey))
	if err != nil {
		return "", "", err
	}

	// Генерация Refresh токена
	refreshBytes := make([]byte, 32) // Произвольная длина
	_, err = rand.Read(refreshBytes)
	if err != nil {
		return "", "", err
	}
	refreshToken := base64.StdEncoding.EncodeToString(refreshBytes)

	return accessSigned, refreshToken, nil
}
