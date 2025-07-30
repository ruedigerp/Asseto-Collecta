package main

// Models - Datenstrukturen (gleich wie im Backend)
// type Config struct {
// 	APIUrl      string
// 	Port        string
// 	Environment string
// 	Debug       bool
// }

// type Employee struct {
// 	ID         uint   `json:"id" gorm:"primaryKey"`
// 	FirstName  string `json:"first_name" gorm:"not null"`
// 	LastName   string `json:"last_name" gorm:"not null"`
// 	Email      string `json:"email" gorm:"unique;not null"`
// 	Department string `json:"department"`

// 	// NEUE Authentication Felder
// 	IsAdmin   bool       `json:"is_admin" gorm:"default:false"` // Admin-Berechtigung
// 	Password  string     `json:"-" gorm:"column:password_hash"` // Passwort-Hash (nicht in JSON)
// 	IsActive  bool       `json:"is_active" gorm:"default:true"` // Account aktiv/deaktiviert
// 	LastLogin *time.Time `json:"last_login,omitempty"`          // Letzter Login

// 	CreatedAt time.Time `json:"created_at"`
// 	UpdatedAt time.Time `json:"updated_at"`
// }

// // Login Request Struktur
// type LoginRequest struct {
// 	Email    string `json:"email" binding:"required,email"`
// 	Password string `json:"password" binding:"required,min=6"`
// }

// // Login Response Struktur
// type LoginResponse struct {
// 	Token     string    `json:"token"`
// 	Employee  Employee  `json:"employee"`
// 	ExpiresAt time.Time `json:"expires_at"`
// }

// // JWT Claims Struktur
// type JWTClaims struct {
// 	EmployeeID uint   `json:"employee_id"`
// 	Email      string `json:"email"`
// 	IsAdmin    bool   `json:"is_admin"`
// 	jwt.StandardClaims
// }

// // Password Change Request
// type ChangePasswordRequest struct {
// 	CurrentPassword string `json:"current_password" binding:"required"`
// 	NewPassword     string `json:"new_password" binding:"required,min=6"`
// 	ConfirmPassword string `json:"confirm_password" binding:"required"`
// }

// // Employee Update Request (ohne Passwort)
// type EmployeeUpdateRequest struct {
// 	FirstName  string `json:"first_name" binding:"required"`
// 	LastName   string `json:"last_name" binding:"required"`
// 	Email      string `json:"email" binding:"required,email"`
// 	Department string `json:"department"`
// 	IsAdmin    bool   `json:"is_admin"`
// 	IsActive   bool   `json:"is_active"`
// }

// type Asset struct {
// 	ID           uint           `json:"id"`
// 	Name         string         `json:"name"`        // NEU: Genaue Bezeichnung
// 	DeviceType   string         `json:"device_type"` // Kategorie
// 	SerialNumber string         `json:"serial_number"`
// 	PurchaseDate time.Time      `json:"purchase_date"`
// 	Price        float64        `json:"price"`
// 	Status       string         `json:"status"`
// 	CurrentUser  *uint          `json:"current_user,omitempty"`
// 	CreatedAt    time.Time      `json:"created_at"`
// 	UpdatedAt    time.Time      `json:"updated_at"`
// 	History      []AssetHistory `json:"history,omitempty"`
// }

// type AssetHistory struct {
// 	ID         uint      `json:"id"`
// 	AssetID    uint      `json:"asset_id"`
// 	Action     string    `json:"action"`
// 	EmployeeID *uint     `json:"employee_id,omitempty"`
// 	FromUserID *uint     `json:"from_user_id,omitempty"`
// 	ToUserID   *uint     `json:"to_user_id,omitempty"`
// 	Date       time.Time `json:"date"`
// 	Notes      string    `json:"notes"`
// 	CreatedAt  time.Time `json:"created_at"`

// 	// Relationships
// 	Asset    Asset     `json:"asset,omitempty"`
// 	Employee *Employee `json:"employee,omitempty"`
// 	FromUser *Employee `json:"from_user,omitempty"`
// 	ToUser   *Employee `json:"to_user,omitempty"`
// }

// // Page Data Structure
// type PageData struct {
// 	Title       string
// 	APIBaseURL  string
// 	Assets      []Asset
// 	Employees   Employee
// 	Error       string
// 	Success     string
// 	CurrentUser User
// 	Template    string
// }

// type User struct {
// 	FirstName string
// 	LastName  string
// 	// ... andere User-Felder
// }

// // Frontend Server Structure
// type FrontendServer struct {
// 	apiURL    string
// 	templates *template.Template
// }
