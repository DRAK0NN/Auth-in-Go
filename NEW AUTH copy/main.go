package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("super_secret_key")
var mockEmail = "user@example.com"

type TokenStore struct {
	sync.Mutex
	tokens map[string]struct {
		RefreshHash string
		IpAddress   string
	}
}

var store = TokenStore{
	tokens: make(map[string]struct {
		RefreshHash string
		IpAddress   string
	}),
}

func generateRefreshToken() (string, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(token), nil
}

func createAccessToken(userID string, ip string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"ip":      ip,
		"exp":     time.Now().Add(time.Minute * 15).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString(jwtKey)
}

func hashRefreshToken(refreshToken string) (string, error) {
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedToken), nil
}

func getTokensHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		http.Error(w, "Отсутствует user_id", http.StatusBadRequest)
		return
	}

	ip := r.RemoteAddr

	accessToken, err := createAccessToken(userID, ip)
	if err != nil {
		http.Error(w, "Ошибка создания - access token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := generateRefreshToken()
	if err != nil {
		http.Error(w, "Ошибка создания - refresh token", http.StatusInternalServerError)
		return
	}

	refreshHash, err := hashRefreshToken(refreshToken)
	if err != nil {
		http.Error(w, "Ошибка хеширования токена - refresh", http.StatusInternalServerError)
		return
	}

	store.Lock()
	store.tokens[userID] = struct {
		RefreshHash string
		IpAddress   string
	}{
		RefreshHash: refreshHash,
		IpAddress:   ip,
	}
	store.Unlock()

	fmt.Fprintf(w, "AccessToken: %s\nRefreshToken: %s", accessToken, refreshToken)
}

func refreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.URL.Query().Get("refresh_token")
	userID := r.URL.Query().Get("user_id")
	if refreshToken == "" || userID == "" {
		http.Error(w, "Отсутсвует refresh_token или user_id", http.StatusBadRequest)
		return
	}

	store.Lock()
	tokenData, exists := store.tokens[userID]
	store.Unlock()
	if !exists {
		http.Error(w, "Пользователь не найден", http.StatusUnauthorized)
		return
	}

	err := bcrypt.CompareHashAndPassword([]byte(tokenData.RefreshHash), []byte(refreshToken))
	if err != nil {
		http.Error(w, "Неверный refresh token", http.StatusUnauthorized)
		return
	}

	newIp := r.RemoteAddr
	if newIp != tokenData.IpAddress {
		fmt.Printf("Sending email to %s: IP address changed\n", mockEmail)
	}

	accessToken, err := createAccessToken(userID, newIp)
	if err != nil {
		http.Error(w, "Ошибка создания - access token", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Новый AccessToken: %s", accessToken)
}

func main() {
	http.HandleFunc("/get-tokens", getTokensHandler)
	http.HandleFunc("/refresh-token", refreshTokenHandler)

	fmt.Println("Server is running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
