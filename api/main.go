package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/context"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var jwtSecret = []byte(getEnv("JWT_SECRET", "your-super-secret-key-change-in-production"))

// Models

// Erweiterte Employee Struktur mit Authentication (Backend + Frontend)
type Employee struct {
	ID         uint   `json:"id" gorm:"primaryKey"`
	FirstName  string `json:"first_name" gorm:"not null"`
	LastName   string `json:"last_name" gorm:"not null"`
	Email      string `json:"email" gorm:"unique;not null"`
	Department string `json:"department"`

	// NEUE Authentication Felder
	IsAdmin   bool       `json:"is_admin" gorm:"default:false"` // Admin-Berechtigung
	Password  string     `json:"-" gorm:"column:password_hash"` // Passwort-Hash (nicht in JSON)
	IsActive  bool       `json:"is_active" gorm:"default:true"` // Account aktiv/deaktiviert
	LastLogin *time.Time `json:"last_login,omitempty"`          // Letzter Login

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Login Request Struktur
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

// Login Response Struktur
type LoginResponse struct {
	Token     string    `json:"token"`
	Employee  Employee  `json:"employee"`
	ExpiresAt time.Time `json:"expires_at"`
}

// JWT Claims Struktur
type JWTClaims struct {
	EmployeeID uint   `json:"employee_id"`
	Email      string `json:"email"`
	IsAdmin    bool   `json:"is_admin"`
	jwt.StandardClaims
}

// Password Change Request
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required,min=6"`
	ConfirmPassword string `json:"confirm_password" binding:"required"`
}

// Employee Update Request (ohne Passwort)
type EmployeeUpdateRequest struct {
	FirstName  string `json:"first_name" binding:"required"`
	LastName   string `json:"last_name" binding:"required"`
	Email      string `json:"email" binding:"required,email"`
	Department string `json:"department"`
	IsAdmin    bool   `json:"is_admin"`
	IsActive   bool   `json:"is_active"`
}

type Asset struct {
	ID           uint           `json:"id" gorm:"primaryKey"`
	Name         string         `json:"name" gorm:"not null"`        // NEU: z.B. "MacBook Air 13""
	DeviceType   string         `json:"device_type" gorm:"not null"` // Kategorie: Laptop, Monitor, etc.
	SerialNumber string         `json:"serial_number" gorm:"unique;not null"`
	PurchaseDate time.Time      `json:"purchase_date"`
	Price        float64        `json:"price"`
	Status       string         `json:"status" gorm:"default:'available'"` // available, assigned, maintenance, retired
	CurrentUser  *uint          `json:"current_user,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	History      []AssetHistory `json:"history,omitempty" gorm:"foreignKey:AssetID"`
}

type AssetHistory struct {
	ID         uint      `json:"id" gorm:"primaryKey"`
	AssetID    uint      `json:"asset_id" gorm:"not null"`
	Action     string    `json:"action" gorm:"not null"` // purchased, assigned, returned, transferred, pool_return
	EmployeeID *uint     `json:"employee_id,omitempty"`
	FromUserID *uint     `json:"from_user_id,omitempty"`
	ToUserID   *uint     `json:"to_user_id,omitempty"`
	Date       time.Time `json:"date"`
	Notes      string    `json:"notes"`
	CreatedAt  time.Time `json:"created_at"`

	// Relationships
	Asset    Asset     `json:"asset,omitempty" gorm:"foreignKey:AssetID"`
	Employee *Employee `json:"employee,omitempty" gorm:"foreignKey:EmployeeID"`
	FromUser *Employee `json:"from_user,omitempty" gorm:"foreignKey:FromUserID"`
	ToUser   *Employee `json:"to_user,omitempty" gorm:"foreignKey:ToUserID"`
}

// Database connections
var db *gorm.DB
var rdb *redis.Client

// Config
// type Config struct {
// 	DatabaseURL string
// 	RedisURL    string
// 	UseRedis    bool
// }

// Generate JWT Token
func generateJWT(employee Employee) (string, time.Time, error) {
	expirationTime := time.Now().Add(24 * time.Hour) // 24 Stunden gültig

	claims := &JWTClaims{
		EmployeeID: employee.ID,
		Email:      employee.Email,
		IsAdmin:    employee.IsAdmin,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    "asset-management-system",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)

	return tokenString, expirationTime, err
}

// Validate JWT Token
func validateJWT(tokenString string) (*JWTClaims, error) {
	claims := &JWTClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

// Hash Password
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// Check Password
func checkPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Generate Random Password
func generateRandomPassword() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)[:12]
}

// Login Handler
func login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var employee Employee
	if err := db.Where("email = ? AND is_active = ?", req.Email, true).First(&employee).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Check if employee has a password set
	if employee.Password == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Account not activated. Please contact an administrator.",
		})
		return
	}

	if !checkPassword(req.Password, employee.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Update last login
	now := time.Now()
	employee.LastLogin = &now
	db.Save(&employee)

	// Generate JWT
	token, expiresAt, err := generateJWT(employee)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// Remove password from response
	employee.Password = ""

	c.JSON(http.StatusOK, LoginResponse{
		Token:     token,
		Employee:  employee,
		ExpiresAt: expiresAt,
	})
}

// Change Password Handler
func changePassword(c *gin.Context) {
	claims, exists := c.Get("claims")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	jwtClaims := claims.(*JWTClaims)

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.NewPassword != req.ConfirmPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Passwords do not match"})
		return
	}

	var employee Employee
	if err := db.First(&employee, jwtClaims.EmployeeID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Employee not found"})
		return
	}

	// Check current password (skip if no password set yet)
	if employee.Password != "" && !checkPassword(req.CurrentPassword, employee.Password) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Current password is incorrect"})
		return
	}

	// Hash new password
	hashedPassword, err := hashPassword(req.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Update password
	employee.Password = hashedPassword
	if err := db.Save(&employee).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password updated successfully"})
}

// Set Password for Employee (Admin only)
func setEmployeePassword(c *gin.Context) {
	claims, exists := c.Get("claims")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	jwtClaims := claims.(*JWTClaims)
	if !jwtClaims.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
		return
	}

	employeeID := c.Param("id")
	var req struct {
		Password string `json:"password" binding:"required,min=6"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var employee Employee
	if err := db.First(&employee, employeeID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Employee not found"})
		return
	}

	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	employee.Password = hashedPassword
	if err := db.Save(&employee).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password set successfully"})
}

// Middleware für JWT Authentication
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Extract token from "Bearer <token>"
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization format"})
			c.Abort()
			return
		}

		claims, err := validateJWT(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Check if employee still exists and is active
		var employee Employee
		if err := db.Where("id = ? AND is_active = ?", claims.EmployeeID, true).First(&employee).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Employee not found or inactive"})
			c.Abort()
			return
		}

		c.Set("claims", claims)
		c.Set("employee", employee)
		c.Next()
	}
}

// Admin-only Middleware
func adminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, exists := c.Get("claims")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		jwtClaims := claims.(*JWTClaims)
		if !jwtClaims.IsAdmin {
			c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// Erweiterte Employee Creation mit Password
func createEmployeeWithAuth(c *gin.Context) {
	var employee Employee
	if err := c.ShouldBindJSON(&employee); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Generate random password if admin
	if employee.IsAdmin {
		tempPassword := generateRandomPassword()
		hashedPassword, err := hashPassword(tempPassword)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}
		employee.Password = hashedPassword

		log.Printf("🔑 Generated temporary password for %s: %s", employee.Email, tempPassword)
	}

	if err := db.Create(&employee).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create employee"})
		return
	}

	// Remove password from response
	employee.Password = ""

	response := gin.H{
		"employee": employee,
		"message":  "Employee created successfully",
	}

	// Include temporary password in response for admins
	if employee.IsAdmin {
		response["temporary_password"] = generateRandomPassword()
	}
	key := "employees:all"
	// Invalidate cache
	ctx := context.Background()
	if err := rdb.Del(ctx, key).Err(); err != nil {
		log.Printf("⚠️ Failed to invalidate cache for key %s: %v", key, err)
	} else {
		log.Printf("✅ Cache invalidated for key: %s", key)
	}

	c.JSON(http.StatusCreated, response)
}

// Initialize database connections
func initDB(config Config) error {
	var err error

	// MySQL connection
	db, err = gorm.Open(mysql.Open(config.DatabaseURL), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect to MySQL: %v", err)
	}

	// Auto-migrate tables
	err = db.AutoMigrate(&Employee{}, &Asset{}, &AssetHistory{})
	if err != nil {
		return fmt.Errorf("failed to migrate database: %v", err)
	}

	// Redis connection (optional)
	if config.UseRedis {
		rdb = redis.NewClient(&redis.Options{
			Addr: config.RedisURL,
		})

		ctx := context.Background()
		_, err = rdb.Ping(ctx).Result()
		if err != nil {
			log.Printf("Redis connection failed: %v", err)
			config.UseRedis = false
		}
	}

	return nil
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		c.Header("Access-Control-Allow-Origin", origin)
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// Redis cache helpers
func getCacheKey(prefix, id string) string {
	return fmt.Sprintf("%s:%s", prefix, id)
}

func setCache(key string, value interface{}, expiration time.Duration) error {
	if rdb == nil {
		return nil
	}

	ctx := context.Background()
	json, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return rdb.Set(ctx, key, json, expiration).Err()
}

func getCache(key string, dest interface{}) error {
	if rdb == nil {
		return fmt.Errorf("redis not available")
	}

	ctx := context.Background()
	val, err := rdb.Get(ctx, key).Result()
	if err != nil {
		return err
	}

	return json.Unmarshal([]byte(val), dest)
}

// Employee handlers
func createEmployee(c *gin.Context) {
	var employee Employee
	if err := c.ShouldBindJSON(&employee); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := db.Create(&employee).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create employee"})
		return
	}

	// Cache the employee
	cacheKey := getCacheKey("employee", strconv.Itoa(int(employee.ID)))
	setCache(cacheKey, employee, time.Hour)

	c.JSON(http.StatusCreated, employee)
}

func getEmployees(c *gin.Context) {
	var employees []Employee

	// Try cache first
	cacheKey := "employees:all"
	if err := getCache(cacheKey, &employees); err != nil {
		// Cache miss, get from database
		if err := db.Find(&employees).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch employees"})
			return
		}

		// Cache the result
		setCache(cacheKey, employees, 30*time.Minute)
	}

	c.JSON(http.StatusOK, employees)
}

func getEmployee(c *gin.Context) {
	id := c.Param("id")
	var employee Employee

	// Try cache first
	cacheKey := getCacheKey("employee", id)
	if err := getCache(cacheKey, &employee); err != nil {
		// Cache miss, get from database
		if err := db.First(&employee, id).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Employee not found"})
			return
		}

		// Cache the result
		setCache(cacheKey, employee, time.Hour)
	}

	c.JSON(http.StatusOK, employee)
}

// Asset handlers
func createAsset(c *gin.Context) {
	var asset Asset
	if err := c.ShouldBindJSON(&asset); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Start transaction
	tx := db.Begin()

	// Create asset
	if err := tx.Create(&asset).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create asset"})
		return
	}

	// Create initial history entry
	history := AssetHistory{
		AssetID: asset.ID,
		Action:  "purchased",
		Date:    asset.PurchaseDate,
		Notes:   "Asset purchased and added to inventory",
	}

	if err := tx.Create(&history).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create asset history"})
		return
	}

	tx.Commit()

	// Cache the individual asset
	cacheKey := getCacheKey("asset", strconv.Itoa(int(asset.ID)))
	setCache(cacheKey, asset, time.Hour)

	// 🔥 WICHTIG: Invalidiere den assets:all Cache!
	if rdb != nil {
		ctx := context.Background()
		rdb.Del(ctx, "assets:all").Err()
		log.Printf("✅ Invalidated assets:all cache after creating asset %d", asset.ID)
	}

	c.JSON(http.StatusCreated, asset)
}

func getAssets(c *gin.Context) {
	var assets []Asset

	// Try cache first
	cacheKey := "assets:all"
	if err := getCache(cacheKey, &assets); err != nil {
		// Cache miss, get from database
		if err := db.Preload("History").Find(&assets).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch assets"})
			return
		}

		// Cache the result
		setCache(cacheKey, assets, 30*time.Minute)
	}

	c.JSON(http.StatusOK, assets)
}

func getAsset(c *gin.Context) {
	id := c.Param("id")
	var asset Asset

	// Try cache first
	cacheKey := getCacheKey("asset", id)
	if err := getCache(cacheKey, &asset); err != nil {
		// Cache miss, get from database
		if err := db.Preload("History").Preload("History.Employee").Preload("History.FromUser").Preload("History.ToUser").First(&asset, id).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Asset not found"})
			return
		}

		// Cache the result
		setCache(cacheKey, asset, time.Hour)
	}

	c.JSON(http.StatusOK, asset)
}

// Asset assignment
type AssignmentRequest struct {
	EmployeeID uint   `json:"employee_id" binding:"required"`
	Notes      string `json:"notes"`
}

func assignAsset(c *gin.Context) {
	assetID := c.Param("id")
	var req AssignmentRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Start transaction
	tx := db.Begin()

	// Get asset
	var asset Asset
	if err := tx.First(&asset, assetID).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusNotFound, gin.H{"error": "Asset not found"})
		return
	}

	// Check if asset is available
	if asset.Status != "available" {
		tx.Rollback()
		c.JSON(http.StatusBadRequest, gin.H{"error": "Asset is not available for assignment"})
		return
	}

	// Check if employee exists
	var employee Employee
	if err := tx.First(&employee, req.EmployeeID).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusNotFound, gin.H{"error": "Employee not found"})
		return
	}

	// Update asset
	asset.Status = "assigned"
	asset.CurrentUser = &req.EmployeeID
	if err := tx.Save(&asset).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update asset"})
		return
	}

	// Create history entry
	history := AssetHistory{
		AssetID:    asset.ID,
		Action:     "assigned",
		EmployeeID: &req.EmployeeID,
		Date:       time.Now(),
		Notes:      req.Notes,
	}

	if err := tx.Create(&history).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create history entry"})
		return
	}

	tx.Commit()

	// Invalidate both individual and list cache
	assetCacheKey := getCacheKey("asset", assetID)
	if rdb != nil {
		ctx := context.Background()
		rdb.Del(ctx, assetCacheKey, "assets:all").Err()
		log.Printf("✅ Invalidated asset cache after assignment")
	}

	c.JSON(http.StatusOK, gin.H{"message": "Asset assigned successfully"})
}

// Asset return
type ReturnRequest struct {
	Notes        string `json:"notes"`
	ReturnToPool bool   `json:"return_to_pool"`
}

func returnAsset(c *gin.Context) {
	assetID := c.Param("id")
	var req ReturnRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Start transaction
	tx := db.Begin()

	// Get asset
	var asset Asset
	if err := tx.First(&asset, assetID).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusNotFound, gin.H{"error": "Asset not found"})
		return
	}

	// Check if asset is assigned
	if asset.Status != "assigned" || asset.CurrentUser == nil {
		tx.Rollback()
		c.JSON(http.StatusBadRequest, gin.H{"error": "Asset is not currently assigned"})
		return
	}

	// Update asset
	fromUserID := asset.CurrentUser
	asset.CurrentUser = nil

	if req.ReturnToPool {
		asset.Status = "available"
	} else {
		asset.Status = "available"
	}

	if err := tx.Save(&asset).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update asset"})
		return
	}

	// Create history entry
	action := "returned"
	if req.ReturnToPool {
		action = "pool_return"
	}

	history := AssetHistory{
		AssetID:    asset.ID,
		Action:     action,
		FromUserID: fromUserID,
		Date:       time.Now(),
		Notes:      req.Notes,
	}

	if err := tx.Create(&history).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create history entry"})
		return
	}

	tx.Commit()

	// Invalidate both individual and list cache
	assetCacheKey := getCacheKey("asset", assetID)
	if rdb != nil {
		ctx := context.Background()
		rdb.Del(ctx, assetCacheKey, "assets:all").Err()
		log.Printf("✅ Invalidated asset cache after return")
	}

	c.JSON(http.StatusOK, gin.H{"message": "Asset returned successfully"})
}

// Asset transfer
type TransferRequest struct {
	ToEmployeeID uint   `json:"to_employee_id" binding:"required"`
	Notes        string `json:"notes"`
}

func transferAsset(c *gin.Context) {
	assetID := c.Param("id")
	var req TransferRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Start transaction
	tx := db.Begin()

	// Get asset
	var asset Asset
	if err := tx.First(&asset, assetID).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusNotFound, gin.H{"error": "Asset not found"})
		return
	}

	// Check if asset is assigned
	if asset.Status != "assigned" || asset.CurrentUser == nil {
		tx.Rollback()
		c.JSON(http.StatusBadRequest, gin.H{"error": "Asset is not currently assigned"})
		return
	}

	// Check if target employee exists
	var employee Employee
	if err := tx.First(&employee, req.ToEmployeeID).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusNotFound, gin.H{"error": "Target employee not found"})
		return
	}

	// Update asset
	fromUserID := asset.CurrentUser
	asset.CurrentUser = &req.ToEmployeeID

	if err := tx.Save(&asset).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update asset"})
		return
	}

	// Create history entry
	history := AssetHistory{
		AssetID:    asset.ID,
		Action:     "transferred",
		FromUserID: fromUserID,
		ToUserID:   &req.ToEmployeeID,
		Date:       time.Now(),
		Notes:      req.Notes,
	}

	if err := tx.Create(&history).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create history entry"})
		return
	}

	tx.Commit()

	// Invalidate both individual and list cache
	assetCacheKey := getCacheKey("asset", assetID)
	if rdb != nil {
		ctx := context.Background()
		rdb.Del(ctx, assetCacheKey, "assets:all").Err()
		log.Printf("✅ Invalidated asset cache after transfer")
	}

	c.JSON(http.StatusOK, gin.H{"message": "Asset transferred successfully"})
}

// Get asset history
func getAssetHistory(c *gin.Context) {
	assetID := c.Param("id")
	var history []AssetHistory

	if err := db.Where("asset_id = ?", assetID).
		Preload("Employee").
		Preload("FromUser").
		Preload("ToUser").
		Order("date DESC").
		Find(&history).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch asset history"})
		return
	}

	c.JSON(http.StatusOK, history)
}

func updateEmployee(c *gin.Context) {
	id := c.Param("id")
	var employee Employee

	// Check if employee exists
	if err := db.First(&employee, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Employee not found"})
		return
	}

	// Bind updated data
	if err := c.ShouldBindJSON(&employee); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Update in database
	if err := db.Save(&employee).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update employee"})
		return
	}

	// Invalidate cache
	if rdb != nil {
		ctx := context.Background()
		empCacheKey := getCacheKey("employee", id)
		rdb.Del(ctx, empCacheKey, "employees:all").Err()
		log.Printf("✅ Invalidated employee cache after update")
	}

	c.JSON(http.StatusOK, employee)
}

func deleteEmployee(c *gin.Context) {
	id := c.Param("id")
	var employee Employee

	// Check if employee exists
	if err := db.First(&employee, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Employee not found"})
		return
	}

	// Check if employee has assigned assets
	var assetCount int64
	db.Model(&Asset{}).Where("current_user = ?", id).Count(&assetCount)
	if assetCount > 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":           "Cannot delete employee with assigned assets",
			"assigned_assets": assetCount,
		})
		return
	}

	// Start transaction
	tx := db.Begin()

	// Update history records to remove employee references
	if err := tx.Model(&AssetHistory{}).Where("employee_id = ?", id).Update("employee_id", nil).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update history records"})
		return
	}

	// Delete employee
	if err := tx.Delete(&employee).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete employee"})
		return
	}

	tx.Commit()

	// Invalidate cache
	if rdb != nil {
		ctx := context.Background()
		empCacheKey := getCacheKey("employee", id)
		rdb.Del(ctx, empCacheKey, "employees:all").Err()
		log.Printf("✅ Invalidated employee cache after deletion")
	}

	c.JSON(http.StatusOK, gin.H{"message": "Employee deleted successfully"})
}

func updateAsset(c *gin.Context) {
	id := c.Param("id")
	var asset Asset
	var updateData Asset

	// Check if asset exists
	if err := db.First(&asset, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Asset not found"})
		return
	}

	// Bind updated data
	if err := c.ShouldBindJSON(&updateData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Preserve certain fields that shouldn't be changed via general update
	updateData.ID = asset.ID
	updateData.CreatedAt = asset.CreatedAt

	// If CurrentUser is being changed, we need to handle this carefully
	oldCurrentUser := asset.CurrentUser
	newCurrentUser := updateData.CurrentUser

	tx := db.Begin()

	// Update asset
	if err := tx.Save(&updateData).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update asset"})
		return
	}

	// If user assignment changed, create history entry
	if (oldCurrentUser == nil && newCurrentUser != nil) ||
		(oldCurrentUser != nil && newCurrentUser == nil) ||
		(oldCurrentUser != nil && newCurrentUser != nil && *oldCurrentUser != *newCurrentUser) {

		var action string
		var notes string

		if oldCurrentUser == nil && newCurrentUser != nil {
			action = "assigned"
			notes = "Asset assigned via update"
		} else if oldCurrentUser != nil && newCurrentUser == nil {
			action = "returned"
			notes = "Asset returned via update"
		} else {
			action = "transferred"
			notes = "Asset transferred via update"
		}

		history := AssetHistory{
			AssetID:    updateData.ID,
			Action:     action,
			FromUserID: oldCurrentUser,
			ToUserID:   newCurrentUser,
			Date:       time.Now(),
			Notes:      notes,
		}

		if newCurrentUser != nil && (oldCurrentUser == nil || action == "assigned") {
			history.EmployeeID = newCurrentUser
		}

		if err := tx.Create(&history).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create history entry"})
			return
		}
	}

	tx.Commit()

	// Invalidate cache
	if rdb != nil {
		ctx := context.Background()
		assetCacheKey := getCacheKey("asset", id)
		rdb.Del(ctx, assetCacheKey, "assets:all").Err()
		log.Printf("✅ Invalidated asset cache after update")
	}

	c.JSON(http.StatusOK, updateData)
}

func deleteAsset(c *gin.Context) {
	id := c.Param("id")
	var asset Asset

	// Check if asset exists
	if err := db.First(&asset, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Asset not found"})
		return
	}

	// Check if asset is currently assigned
	if asset.CurrentUser != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":       "Cannot delete asset that is currently assigned",
			"assigned_to": *asset.CurrentUser,
		})
		return
	}

	tx := db.Begin()

	// Delete history records
	if err := tx.Where("asset_id = ?", id).Delete(&AssetHistory{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete asset history"})
		return
	}

	// Delete asset
	if err := tx.Delete(&asset).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete asset"})
		return
	}

	tx.Commit()

	// Invalidate cache
	if rdb != nil {
		ctx := context.Background()
		assetCacheKey := getCacheKey("asset", id)
		rdb.Del(ctx, assetCacheKey, "assets:all").Err()
		log.Printf("✅ Invalidated asset cache after deletion")
	}

	c.JSON(http.StatusOK, gin.H{"message": "Asset deleted successfully"})
}

func unassignAsset(c *gin.Context) {
	assetID := c.Param("id")

	type UnassignRequest struct {
		Notes string `json:"notes"`
		Force bool   `json:"force"` // Force unassign even if status conflicts
	}

	var req UnassignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Allow empty body
		req = UnassignRequest{Notes: "Asset unassigned via API"}
	}

	tx := db.Begin()

	var asset Asset
	if err := tx.First(&asset, assetID).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusNotFound, gin.H{"error": "Asset not found"})
		return
	}

	if asset.CurrentUser == nil && !req.Force {
		tx.Rollback()
		c.JSON(http.StatusBadRequest, gin.H{"error": "Asset is not currently assigned"})
		return
	}

	fromUserID := asset.CurrentUser
	asset.CurrentUser = nil
	asset.Status = "available"

	if err := tx.Save(&asset).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update asset"})
		return
	}

	// Create history entry
	history := AssetHistory{
		AssetID:    asset.ID,
		Action:     "returned",
		FromUserID: fromUserID,
		Date:       time.Now(),
		Notes:      req.Notes,
	}

	if err := tx.Create(&history).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create history entry"})
		return
	}

	tx.Commit()

	// Invalidate cache
	if rdb != nil {
		ctx := context.Background()
		assetCacheKey := getCacheKey("asset", assetID)
		rdb.Del(ctx, assetCacheKey, "assets:all").Err()
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Asset unassigned successfully",
		"asset":   asset,
	})
}

func getEmployeeAssets(c *gin.Context) {
	employeeID := c.Param("id")
	var assets []Asset

	if err := db.Where("current_user = ?", employeeID).Preload("History").Find(&assets).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch employee assets"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"employee_id": employeeID,
		"assets":      assets,
		"count":       len(assets),
	})
}

// Bulk operations
func bulkAssignAssets(c *gin.Context) {
	type BulkAssignRequest struct {
		AssetIDs   []uint `json:"asset_ids" binding:"required"`
		EmployeeID uint   `json:"employee_id" binding:"required"`
		Notes      string `json:"notes"`
	}

	var req BulkAssignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if employee exists
	var employee Employee
	if err := db.First(&employee, req.EmployeeID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Employee not found"})
		return
	}

	tx := db.Begin()

	var results []gin.H
	successCount := 0

	for _, assetID := range req.AssetIDs {
		var asset Asset
		if err := tx.First(&asset, assetID).Error; err != nil {
			results = append(results, gin.H{
				"asset_id": assetID,
				"success":  false,
				"error":    "Asset not found",
			})
			continue
		}

		if asset.Status != "available" {
			results = append(results, gin.H{
				"asset_id": assetID,
				"success":  false,
				"error":    "Asset not available",
			})
			continue
		}

		// Update asset
		asset.Status = "assigned"
		asset.CurrentUser = &req.EmployeeID

		if err := tx.Save(&asset).Error; err != nil {
			results = append(results, gin.H{
				"asset_id": assetID,
				"success":  false,
				"error":    "Failed to update asset",
			})
			continue
		}

		// Create history entry
		history := AssetHistory{
			AssetID:    asset.ID,
			Action:     "assigned",
			EmployeeID: &req.EmployeeID,
			Date:       time.Now(),
			Notes:      req.Notes,
		}

		if err := tx.Create(&history).Error; err != nil {
			results = append(results, gin.H{
				"asset_id": assetID,
				"success":  false,
				"error":    "Failed to create history",
			})
			continue
		}

		results = append(results, gin.H{
			"asset_id": assetID,
			"success":  true,
		})
		successCount++
	}

	tx.Commit()

	// Invalidate cache
	if rdb != nil {
		ctx := context.Background()
		rdb.Del(ctx, "assets:all").Err()
	}

	c.JSON(http.StatusOK, gin.H{
		"message":       fmt.Sprintf("Bulk assignment completed: %d/%d successful", successCount, len(req.AssetIDs)),
		"results":       results,
		"success_count": successCount,
		"total_count":   len(req.AssetIDs),
	})
}

func flushCache(c *gin.Context) {
	if rdb == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Redis not available"})
		return
	}

	ctx := context.Background()

	// Flush all asset-related cache keys
	keys := []string{"assets:all", "employees:all"}

	// Get all individual asset cache keys
	assetKeys, err := rdb.Keys(ctx, "asset:*").Result()
	if err == nil {
		keys = append(keys, assetKeys...)
	}

	// Get all individual employee cache keys
	empKeys, err := rdb.Keys(ctx, "employee:*").Result()
	if err == nil {
		keys = append(keys, empKeys...)
	}

	// Delete all keys
	if len(keys) > 0 {
		deleted, err := rdb.Del(ctx, keys...).Result()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to flush cache"})
			return
		}

		log.Printf("🗑️ Flushed %d cache keys", deleted)
		c.JSON(http.StatusOK, gin.H{
			"message":      "Cache flushed successfully",
			"keys_deleted": deleted,
			"keys":         keys,
		})
	} else {
		c.JSON(http.StatusOK, gin.H{"message": "No cache keys to flush"})
	}
}

func getCacheStats(c *gin.Context) {
	if rdb == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Redis not available"})
		return
	}

	ctx := context.Background()

	// Get cache statistics
	assetKeys, _ := rdb.Keys(ctx, "asset:*").Result()
	empKeys, _ := rdb.Keys(ctx, "employee:*").Result()

	stats := gin.H{
		"redis_connected":      true,
		"individual_assets":    len(assetKeys),
		"individual_employees": len(empKeys),
		"list_caches":          gin.H{},
	}

	// Check if list caches exist
	if exists, _ := rdb.Exists(ctx, "assets:all").Result(); exists > 0 {
		ttl, _ := rdb.TTL(ctx, "assets:all").Result()
		stats["list_caches"].(gin.H)["assets:all"] = gin.H{
			"exists":      true,
			"ttl_seconds": int(ttl.Seconds()),
		}
	}

	if exists, _ := rdb.Exists(ctx, "employees:all").Result(); exists > 0 {
		ttl, _ := rdb.TTL(ctx, "employees:all").Result()
		stats["list_caches"].(gin.H)["employees:all"] = gin.H{
			"exists":      true,
			"ttl_seconds": int(ttl.Seconds()),
		}
	}

	c.JSON(http.StatusOK, stats)
}

// Setup routes
func setupRoutes(config Config) *gin.Engine {
	r := gin.Default()

	r.Use(corsMiddleware())

	// Public routes (keine Authentication erforderlich)
	public := r.Group("/")
	{
		public.GET("/health", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"status":    "healthy",
				"service":   "asset-management-api",
				"timestamp": time.Now(),
				"version":   config.VERSION,
				"database":  getDatabaseStatus(),
				"redis":     getRedisStatus(),
			})
		})

		public.GET("/", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"message": "Asset Management API",
				"version": config.VERSION,
				"auth":    "required",
				"endpoints": []string{
					"POST /auth/login",
					"GET /health",
				},
			})
		})

		// Authentication routes
		auth := public.Group("/auth")
		{
			auth.POST("/login", login)
		}
	}

	// Protected routes (Authentication erforderlich)
	protected := r.Group("/")
	protected.Use(authMiddleware())
	{
		// User routes (alle authentifizierten Benutzer)
		user := protected.Group("/user")
		{
			user.POST("/change-password", changePassword)
			user.GET("/profile", func(c *gin.Context) {
				employee, _ := c.Get("employee")
				emp := employee.(Employee)
				emp.Password = "" // Remove password from response
				c.JSON(http.StatusOK, emp)
			})
		}

		// Employee routes (alle authentifizierten Benutzer können lesen)
		protected.GET("/employees", getEmployees)
		protected.GET("/employees/:id", getEmployee)

		// Asset routes (alle authentifizierten Benutzer)
		protected.GET("/assets", getAssets)
		protected.GET("/assets/:id", getAsset)
		protected.GET("/assets/:id/history", getAssetHistory)

		// Admin-only routes
		admin := protected.Group("/")
		admin.Use(adminMiddleware())
		{
			// Employee management (nur Admins)
			admin.POST("/employees", createEmployeeWithAuth)
			admin.PUT("/employees/:id", updateEmployee)
			admin.DELETE("/employees/:id", deleteEmployee)
			admin.POST("/employees/:id/set-password", setEmployeePassword)

			// Asset management (nur Admins)
			admin.POST("/assets", createAsset)
			admin.PUT("/assets/:id", updateAsset)
			admin.DELETE("/assets/:id", deleteAsset)

			// Asset operations (nur Admins)
			admin.POST("/assets/:id/assign", assignAsset)
			admin.POST("/assets/:id/unassign", unassignAsset)
			admin.POST("/assets/:id/return", returnAsset)
			admin.POST("/assets/:id/transfer", transferAsset)
			admin.POST("/assets/bulk-assign", bulkAssignAssets)

			// Cache management (nur Admins)
			admin.POST("/admin/cache/flush", flushCache)
			admin.GET("/admin/cache/stats", getCacheStats)
		}
	}

	return r
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

type Config struct {
	RedisURL    string
	UseRedis    bool
	REDIS_HOST  string
	REDIS_PORT  string
	DB_HOST     string
	DB_PORT     string
	DB_USER     string
	DB_PASS     string
	DB_NAME     string
	DatabaseURL string
	VERSION     string
}

func getEnvBool(key string, defaultValue bool) bool {
	val := getEnv(key, fmt.Sprintf("%t", defaultValue))
	result, err := strconv.ParseBool(val)
	if err != nil {
		return defaultValue
	}
	return result
}

func loadConfig() Config {
	return Config{
		RedisURL:   getEnv("REDISURL", "localhost:6379"),
		UseRedis:   getEnvBool("UseRedis", true),
		REDIS_PORT: getEnv("REDIS_PORT", "6379"),
		REDIS_HOST: getEnv("REDIS_HOST", "localhost"),
		DB_HOST:    getEnv("DB_HOST", "localhost"),
		DB_PORT:    getEnv("DB_PORT", "3306"),
		DB_USER:    getEnv("DB_USER", "asset_user"),
		DB_PASS:    getEnv("DB_PASS", "asset_password"),
		DB_NAME:    getEnv("DB_NAME", "asset_db"),
		VERSION:    getEnv("VERSION", "v0.0.1"),
	}
}

func main() {
	config := loadConfig()
	config.DatabaseURL = fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local", config.DB_USER, config.DB_PASS, config.DB_HOST, config.DB_PORT, config.DB_NAME)
	config.RedisURL = fmt.Sprintf("%s:%s", config.REDIS_HOST, config.REDIS_PORT)

	// Initialize database
	if err := initDB(config); err != nil {
		log.Fatal("Failed to initialize database:", err)
	}

	// Setup routes
	r := setupRoutes(config)

	// Start server
	log.Println("Starting server on :8090")
	if err := r.Run(":8090"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

func getDatabaseStatus() string {
	if db != nil {
		sqlDB, err := db.DB()
		if err != nil {
			return "error"
		}

		if err := sqlDB.Ping(); err != nil {
			return "disconnected"
		}
		return "connected"
	}
	return "not_configured"
}

func getRedisStatus() string {
	if rdb != nil {
		ctx := context.Background()
		if err := rdb.Ping(ctx).Err(); err != nil {
			return "disconnected"
		}
		return "connected"
	}
	return "not_configured"
}
