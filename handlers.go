package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// RegisterHandler обрабатывает регистрацию нового пользователя
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := parseJSONRequest(r, &req); err != nil {
		sendErrorResponse(w, fmt.Sprintf("%v", err), http.StatusBadRequest)
		return
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	if err := validateRegisterRequest(&req); err != nil {
		sendErrorResponse(w, fmt.Sprintf("Validation error: %v", err), http.StatusBadRequest)
		return
	}

	userExists, err := UserExistsByEmail(req.Email)
	if err != nil {
		sendErrorResponse(w, "Database error", http.StatusInternalServerError)
		return
	}

	if userExists {
		sendErrorResponse(w, "User already exists", http.StatusConflict)
		return
	}

	hashedPassword, err := HashPassword(req.Password)
	if err != nil {
		sendErrorResponse(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	user, err := CreateUser(req.Email, req.Username, string(hashedPassword))
	if err != nil {
		sendErrorResponse(w, "Database error", http.StatusInternalServerError)
		return
	}

	token, err := GenerateToken(*user)
	if err != nil {
		sendErrorResponse(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	response := TokenResponse{
		Token: token,
		User:  *user,
	}

	sendJSONResponse(w, response, http.StatusCreated)
}

// LoginHandler обрабатывает вход пользователя
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	req := LoginRequest{}
	if err := parseJSONRequest(r, &req); err != nil {
		sendErrorResponse(w, fmt.Sprintf("%v", err), http.StatusBadRequest)
		return
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if err := validateLoginRequest(&req); err != nil {
		sendErrorResponse(w, fmt.Sprintf("%v", err), http.StatusBadRequest)
		return
	}

	user, err := GetUserByEmail(req.Email)
	if err != nil {
		log.Printf("Database error: %v", err)
		sendErrorResponse(w, "Database error", http.StatusInternalServerError)
		return
	}

	if user == nil || !CheckPassword(req.Password, user.PasswordHash) {
		sendErrorResponse(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	token, err := GenerateToken(*user)
	if err != nil {
		log.Printf("Error generating token: %v", err)
		sendErrorResponse(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	response := TokenResponse{
		Token: token,
		User:  *user,
	}

	sendJSONResponse(w, response, http.StatusAccepted)
}

// ProfileHandler возвращает профиль текущего пользователя
func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		sendErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := GetUserIDFromContext(r)
	if !ok {
		sendErrorResponse(w, "Bad request", http.StatusBadRequest)
		return
	}

	user, err := GetUserByID(userID)
	if err != nil {
		sendErrorResponse(w, fmt.Sprintf("%v", err), http.StatusNotFound)
		return
	}

	sendJSONResponse(w, user, http.StatusOK)
}

// HealthHandler проверяет состояние сервиса
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	// Проверяем подключение к БД
	if db != nil {
		if err := db.Ping(); err != nil {
			http.Error(w, "Database connection failed", http.StatusServiceUnavailable)
			return
		}
	}

	// Возвращаем статус OK
	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{
		"status":  "ok",
		"message": "Service is running",
	}
	json.NewEncoder(w).Encode(response)
}

// sendJSONResponse отправляет JSON ответ (вспомогательная функция)
func sendJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// sendErrorResponse отправляет JSON ответ с ошибкой (вспомогательная функция)
func sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]string{"error": message}
	json.NewEncoder(w).Encode(response)
}

// parseJSONRequest парсит JSON из тела запроса (вспомогательная функция)
func parseJSONRequest(r *http.Request, v interface{}) error {
	if r.Body == nil {
		return fmt.Errorf("request body is empty")
	}
	defer r.Body.Close()

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields() // Строгая проверка полей

	return decoder.Decode(v)
}

// validateRegisterRequest валидирует данные регистрации
func validateRegisterRequest(req *RegisterRequest) error {
	if err := ValidateEmail(req.Email); err != nil {
		return err
	}

	if err := ValidateUsername(req.Username); err != nil {
		return err
	}

	if err := ValidatePassword(req.Password); err != nil {
		return err
	}

	return nil
}

// validateLoginRequest валидирует данные входа
func validateLoginRequest(req *LoginRequest) error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}

	if req.Password == "" {
		return fmt.Errorf("password is required")
	}

	return nil
}
