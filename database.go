package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

// Глобальная переменная для подключения к БД
var db *sql.DB

// InitDB инициализирует подключение к базе данных
func InitDB() error {
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		getEnv("POSTGRES_HOST", "localhost"),
		getEnv("POSTGRES_PORT", "5432"),
		getEnv("POSTGRES_USER", "postgres"),
		getEnv("POSTGRES_PASSWORD", "postgres"),
		getEnv("POSTGRES_DB", "secure_service"),
	)

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}

	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %v", err)
	}

	return nil
}

// CloseDB закрывает соединение с базой данных
func CloseDB() {
	if db != nil {
		db.Close()
	}
}

// CreateUser создает нового пользователя в базе данных
func CreateUser(email, username, passwordHash string) (*User, error) {
	u := User{
		Email:        email,
		Username:     username,
		PasswordHash: passwordHash,
	}

	query := `
		INSERT INTO users (email, username, password_hash) 
		VALUES($1, $2, $3)
		RETURNING id, created_at
	`

	err := db.QueryRow(query, email, username, passwordHash).Scan(&u.ID, &u.CreatedAt)
	if err != nil {
		return nil, err
	}

	return &u, nil
}

// GetUserByEmail находит пользователя по email
func GetUserByEmail(email string) (*User, error) {
	var u User = User{Email: email}

	query := `SELECT id, username, password_hash, created_at FROM users WHERE email = $1`

	err := db.QueryRow(query, u.Email).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}

		return nil, err
	}

	return &u, nil
}

// GetUserByID находит пользователя по ID
func GetUserByID(userID int) (*User, error) {
	var u User = User{ID: userID}

	query := `SELECT email, username, password_hash, created_at FROM users WHERE id = $1`

	err := db.QueryRow(query, u.ID).Scan(&u.Email, &u.Username, &u.PasswordHash, &u.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}

		return nil, err
	}

	return &u, nil
}

// UserExistsByEmail проверяет, существует ли пользователь с данным email
func UserExistsByEmail(email string) (bool, error) {
	var userExists bool

	query := `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`

	err := db.QueryRow(query, email).Scan(&userExists)
	if err != nil {
		return false, err
	}

	return userExists, nil
}

// GetDB возвращает подключение к базе данных (для тестирования)
func GetDB() *sql.DB {
	return db
}
