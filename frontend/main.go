package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	// "crypto/rand"
	// "time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

// Models - Datenstrukturen (gleich wie im Backend)
type Config struct {
	APIUrl      string
	Port        string
	Environment string
	Debug       bool
}

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
	ID           uint           `json:"id"`
	Name         string         `json:"name"`        // NEU: Genaue Bezeichnung
	DeviceType   string         `json:"device_type"` // Kategorie
	SerialNumber string         `json:"serial_number"`
	PurchaseDate time.Time      `json:"purchase_date"`
	Price        float64        `json:"price"`
	Status       string         `json:"status"`
	CurrentUser  *uint          `json:"current_user,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	History      []AssetHistory `json:"history,omitempty"`
}

type AssetHistory struct {
	ID         uint      `json:"id"`
	AssetID    uint      `json:"asset_id"`
	Action     string    `json:"action"`
	EmployeeID *uint     `json:"employee_id,omitempty"`
	FromUserID *uint     `json:"from_user_id,omitempty"`
	ToUserID   *uint     `json:"to_user_id,omitempty"`
	Date       time.Time `json:"date"`
	Notes      string    `json:"notes"`
	CreatedAt  time.Time `json:"created_at"`

	// Relationships
	Asset    Asset     `json:"asset,omitempty"`
	Employee *Employee `json:"employee,omitempty"`
	FromUser *Employee `json:"from_user,omitempty"`
	ToUser   *Employee `json:"to_user,omitempty"`
}

// Page Data Structure
type PageData struct {
	Title       string
	APIBaseURL  string
	Assets      []Asset
	Employees   []Employee
	Employee    *Employee
	Error       string
	Success     string
	CurrentUser Employee
	Template    string
	Version     string
	Stage       string
}

type User struct {
	FirstName string
	LastName  string
	// ... andere User-Felder
}

// Frontend Server Structure
type FrontendServer struct {
	apiURL    string
	templates *template.Template
}

// API Client für Frontend
type APIClient struct {
	baseURL string
	client  *http.Client
	token   string
}

// CORS Middleware für Frontend
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// Template-Funktionen
func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"formatDate": func(t time.Time) string {
			return t.Format("02.01.2006")
		},
		"formatDateTime": func(t time.Time) string {
			return t.Format("02.01.2006 15:04")
		},
		"formatPrice": func(price float64) string {
			return fmt.Sprintf("%.2f €", price)
		},
		"getStatusClass": func(status string) string {
			switch status {
			case "available":
				return "bg-green-100 text-green-800"
			case "assigned":
				return "bg-blue-100 text-blue-800"
			case "maintenance":
				return "bg-yellow-100 text-yellow-800"
			case "retired":
				return "bg-red-100 text-red-800"
			default:
				return "bg-gray-100 text-gray-800"
			}
		},
		"getStatusText": func(status string) string {
			switch status {
			case "available":
				return "Verfügbar"
			case "assigned":
				return "Zugewiesen"
			case "maintenance":
				return "Wartung"
			case "retired":
				return "Ausgemustert"
			default:
				return status
			}
		},
		"getActionIcon": func(action string) string {
			switch action {
			case "purchased":
				return "fa-shopping-cart text-green-600"
			case "assigned":
				return "fa-user-plus text-blue-600"
			case "returned":
				return "fa-undo text-orange-600"
			case "transferred":
				return "fa-exchange-alt text-purple-600"
			case "pool_return":
				return "fa-warehouse text-gray-600"
			default:
				return "fa-clock text-gray-400"
			}
		},
		"getActionText": func(action string) string {
			switch action {
			case "purchased":
				return "Gekauft"
			case "assigned":
				return "Zugewiesen"
			case "returned":
				return "Zurückgegeben"
			case "transferred":
				return "Übertragen"
			case "pool_return":
				return "In Pool zurückgegeben"
			default:
				return action
			}
		},
		"timeSince": func(t time.Time) string {
			now := time.Now()
			diff := now.Sub(t)
			days := int(diff.Hours() / 24)
			hours := int(diff.Hours())
			minutes := int(diff.Minutes())

			if days > 0 {
				if days == 1 {
					return "1 Tag"
				}
				return fmt.Sprintf("%d Tagen", days)
			} else if hours > 0 {
				if hours == 1 {
					return "1 Stunde"
				}
				return fmt.Sprintf("%d Stunden", hours)
			} else if minutes > 0 {
				if minutes == 1 {
					return "1 Minute"
				}
				return fmt.Sprintf("%d Minuten", minutes)
			} else {
				return "gerade eben"
			}
		},
		"add": func(a, b int) int {
			return a + b
		},
		"sub": func(a, b int) int {
			return a - b
		},
		"toJson": func(v interface{}) template.JS {
			jsonBytes, err := json.Marshal(v)
			if err != nil {
				return template.JS("null")
			}
			return template.JS(string(jsonBytes))
		},
		"len": func(items interface{}) int {
			switch v := items.(type) {
			case []Asset:
				return len(v)
			case []Employee:
				return len(v)
			case []AssetHistory:
				return len(v)
			default:
				return 0
			}
		},
		"substr": func(s string, start, length int) string {
			if start < 0 || start >= len(s) {
				return ""
			}
			end := start + length
			if end > len(s) {
				end = len(s)
			}
			return s[start:end]
		},
		"slice": func(s string, start, end int) string {
			if start < 0 || start >= len(s) {
				return ""
			}
			if end > len(s) {
				end = len(s)
			}
			if end <= start {
				return ""
			}
			return s[start:end]
		},
		// Employee-Name per ID finden
		"getEmployeeName": func(employees []Employee, userID interface{}) string {
			if userID == nil {
				return "Nicht zugewiesen"
			}

			// Konvertiere userID zu uint
			var targetID uint
			switch v := userID.(type) {
			case uint:
				targetID = v
			case *uint:
				if v != nil {
					targetID = *v
				} else {
					return "Nicht zugewiesen"
				}
			case int:
				targetID = uint(v)
			case float64:
				targetID = uint(v)
			default:
				return fmt.Sprintf("User ID: %v", userID)
			}

			// Finde Employee
			for _, emp := range employees {
				if emp.ID == targetID {
					return fmt.Sprintf("%s %s", emp.FirstName, emp.LastName)
				}
			}

			return fmt.Sprintf("User ID: %d (nicht gefunden)", targetID)
		},
		// Asset-Employee Verknüpfungsfunktionen
		"isAssetAssignedToEmployee": func(asset Asset, employeeID uint) bool {
			if asset.CurrentUser == nil {
				return false
			}
			return *asset.CurrentUser == employeeID
		},
		"getAssetsForEmployee": func(assets []Asset, employeeID uint) []Asset {
			var result []Asset
			for _, asset := range assets {
				if asset.CurrentUser != nil && *asset.CurrentUser == employeeID {
					result = append(result, asset)
				}
			}
			return result
		},
		"countAssetsForEmployee": func(assets []Asset, employeeID uint) int {
			count := 0
			for _, asset := range assets {
				if asset.CurrentUser != nil && *asset.CurrentUser == employeeID {
					count++
				}
			}
			return count
		},
		// NEUE FUNKTIONEN für Pointer-Vergleiche
		"isCurrentUser": func(currentUser *uint, employeeID uint) bool {
			if currentUser == nil {
				return false
			}
			return *currentUser == employeeID
		},
		"getCurrentUserID": func(currentUser *uint) uint {
			if currentUser == nil {
				return 0
			}
			return *currentUser
		},
		"hasCurrentUser": func(currentUser *uint) bool {
			return currentUser != nil
		},
		"getInitials": func(employees []Employee, userID interface{}) string {
			if userID == nil {
				return "?"
			}

			// Konvertiere userID zu uint
			var targetID uint
			switch v := userID.(type) {
			case uint:
				targetID = v
			case *uint:
				if v != nil {
					targetID = *v
				} else {
					return "?"
				}
			case int:
				targetID = uint(v)
			case float64:
				targetID = uint(v)
			default:
				return "?"
			}

			// Finde Employee und erstelle Initialen
			for _, emp := range employees {
				if emp.ID == targetID {
					firstName := emp.FirstName
					lastName := emp.LastName
					if len(firstName) > 0 && len(lastName) > 0 {
						return string(firstName[0]) + string(lastName[0])
					} else if len(firstName) > 0 {
						return string(firstName[0])
					} else if len(lastName) > 0 {
						return string(lastName[0])
					}
				}
			}

			return "?"
		},
		"eq": func(a, b interface{}) bool {
			return a == b
		},
		"mul": func(a, b int) int {
			return a * b
		},
		"div": func(a, b int) int {
			if b == 0 {
				return 0
			}
			return a / b
		},
		"percentage": func(part, total int) int {
			if total == 0 {
				return 0
			}
			return (part * 100) / total
		},
		"deref": func(ptr interface{}) interface{} {
			if ptr == nil {
				return nil
			}
			v := reflect.ValueOf(ptr)
			if v.Kind() == reflect.Ptr {
				if v.IsNil() {
					return nil
				}
				return v.Elem().Interface()
			}
			return ptr
		},
	}
}

func NewFrontendServer(apiURL string) *FrontendServer {
	// Load all templates
	tmpl := template.New("").Funcs(templateFuncs())

	// Parse templates if they exist
	tmpl = template.Must(tmpl.ParseGlob("templates/*.html"))

	return &FrontendServer{
		apiURL:    apiURL,
		templates: tmpl,
	}
}

// Frontend Authentication Handlers - Fügen Sie diese zu Ihrer Frontend main.go hinzu

// Login page handler
func (fs *FrontendServer) LoginHandler(c *gin.Context) {
	data := PageData{
		Title:      "Login",
		APIBaseURL: fs.apiURL,
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := fs.templates.ExecuteTemplate(c.Writer, "login.html", data); err != nil {
		log.Printf("Template error: %v", err)
		c.String(http.StatusInternalServerError, "Template error: %v", err)
	}
}

// Logout handler
func (fs *FrontendServer) LogoutHandler(c *gin.Context) {
	log.Printf("👋 User logging out from IP: %s", c.ClientIP())

	// 1. AGGRESSIVES COOKIE-LÖSCHEN mit mehreren Methoden
	// Methode 1: Standard Cookie löschen
	c.SetCookie("auth_token", "", -1, "/", "", false, true)

	// Methode 2: Explizit auf "deleted" setzen und Vergangenheits-Datum
	c.SetCookie("auth_token", "deleted", -86400, "/", "", false, true)

	// Methode 3: Auch für verschiedene Pfade löschen (falls Cookie woanders gesetzt wurde)
	c.SetCookie("auth_token", "", -1, "", "", false, true)

	// 2. OPTIONAL: TOKEN BEIM BACKEND INVALIDIEREN
	// Wenn Sie Server-side Token-Blacklisting haben:
	token := fs.extractToken(c)
	if token != "" {
		go func() {
			// Async backend-call um Token zu invalidieren
			client := &http.Client{Timeout: 5 * time.Second}
			req, err := http.NewRequest("POST", fs.apiURL+"/auth/logout", nil)
			if err == nil {
				req.Header.Set("Authorization", token)
				resp, err := client.Do(req)
				if err == nil {
					resp.Body.Close()
					log.Printf("✅ Token invalidated on backend")
				} else {
					log.Printf("⚠️ Failed to invalidate token on backend: %v", err)
				}
			}
		}()
	}

	// 3. HEADERS SETZEN UM CACHING ZU VERHINDERN
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")

	// 4. KURZE PAUSE VOR REDIRECT (gibt Browser Zeit Cookie zu verarbeiten)
	time.Sleep(100 * time.Millisecond)

	log.Printf("✅ Logout completed, redirecting to login")

	// 5. REDIRECT ZUR LOGIN-SEITE
	c.Redirect(http.StatusSeeOther, "/login?message="+url.QueryEscape("Sie wurden erfolgreich abgemeldet"))
}

func (fs *FrontendServer) LogoutHandlerWithIntermediate(c *gin.Context) {
	log.Printf("👋 User logging out from IP: %s", c.ClientIP())

	// 1. TOKEN FÜR BACKEND-INVALIDIERUNG
	token := fs.extractToken(c)
	if token != "" {
		log.Printf("🔑 Found token to invalidate: %s", token[:20]+"...")
		go fs.invalidateTokenBackend(token)
	}

	// 2. COOKIE NUKLEAR LÖSCHEN
	fs.clearAllAuthCookies(c)

	// 3. ANTI-CACHE HEADERS
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate, proxy-revalidate")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")

	// 4. VOLLSTÄNDIGE LOGOUT-SEITE MIT STORAGE-CLEANUP
	logoutHTML := `
<!DOCTYPE html>
<html>
<head>
    <title>Abmeldung erfolgreich</title>
    <meta charset="utf-8">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <style>
        body { 
            font-family: Arial, sans-serif; 
            text-align: center; 
            padding: 50px; 
            background: #f8f9fa;
        }
        .message { 
            background: #d4edda; 
            color: #155724; 
            padding: 30px; 
            border-radius: 8px; 
            margin: 20px auto; 
            max-width: 500px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .countdown { 
            font-size: 18px; 
            font-weight: bold; 
            color: #007bff; 
        }
        .debug { 
            background: #f8f9fa; 
            border: 1px solid #dee2e6; 
            padding: 15px; 
            margin: 20px auto; 
            max-width: 700px; 
            font-family: monospace; 
            font-size: 12px; 
            text-align: left;
            border-radius: 5px;
        }
        .status-ok { color: #28a745; }
        .status-warning { color: #ffc107; }
        .status-error { color: #dc3545; }
    </style>
</head>
<body>
    <div class="message">
        <h2>✅ Abmeldung erfolgreich</h2>
        <p>Sie wurden erfolgreich abgemeldet.</p>
        <p>Alle Sitzungsdaten werden gelöscht...</p>
        <p>Weiterleitung in <span id="countdown" class="countdown">5</span> Sekunden...</p>
        <p><a href="/login" onclick="completeLogout()">Sofort zur Login-Seite</a></p>
    </div>
    
    <div class="debug" id="debug">
        <strong>🔍 Logout Debug Info:</strong><br><br>
        
        <strong>📊 Vor Cleanup:</strong><br>
        Cookies: <span id="cookies-before"></span><br>
        localStorage Items: <span id="localStorage-before"></span><br>
        sessionStorage Items: <span id="sessionStorage-before"></span><br><br>
        
        <strong>🗑️ Cleanup Status:</strong><br>
        <span id="cleanup-status">Wird ausgeführt...</span><br><br>
        
        <strong>✅ Nach Cleanup:</strong><br>
        Cookies: <span id="cookies-after"></span><br>
        localStorage Items: <span id="localStorage-after"></span><br>
        sessionStorage Items: <span id="sessionStorage-after"></span><br>
    </div>

    <script>
        console.log('🔥 LOGOUT: Starting complete session cleanup...');
        
        // HILFSFUNKTIONEN
        function getCookieCount() {
            return document.cookie ? document.cookie.split(';').length : 0;
        }
        
        function getStorageCount(storage) {
            try {
                return storage ? storage.length : 0;
            } catch (e) {
                return 'Error: ' + e.message;
            }
        }
        
        function getAllStorageKeys(storage) {
            try {
                if (!storage) return [];
                const keys = [];
                for (let i = 0; i < storage.length; i++) {
                    keys.push(storage.key(i));
                }
                return keys;
            } catch (e) {
                return ['Error: ' + e.message];
            }
        }
        
        // INITIAL STATUS ANZEIGEN
        document.getElementById('cookies-before').textContent = 
            document.cookie || 'keine';
        document.getElementById('localStorage-before').textContent = 
            getStorageCount(localStorage) + ' (' + getAllStorageKeys(localStorage).join(', ') + ')';
        document.getElementById('sessionStorage-before').textContent = 
            getStorageCount(sessionStorage) + ' (' + getAllStorageKeys(sessionStorage).join(', ') + ')';
        
        // VOLLSTÄNDIGE SESSION-CLEANUP FUNKTION
        function completeLogout() {
            console.log('🗑️ Starting complete logout cleanup...');
            
            let cleanupSteps = [];
            
            // 1. COOKIES LÖSCHEN
            try {
                console.log('🍪 Clearing cookies...');
                const cookieNames = ['auth_token', 'session', 'token', 'jwt', 'user', 'login'];
                const paths = ['/', '', '/assets', '/employees', '/admin'];
                const domains = ['', 'localhost', '.localhost', window.location.hostname, '.' + window.location.hostname];
                
                let cookiesCleaned = 0;
                cookieNames.forEach(name => {
                    paths.forEach(path => {
                        domains.forEach(domain => {
                            // Mehrere Löschmethoden
                            document.cookie = name + '=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=' + path + '; domain=' + domain + ';';
                            document.cookie = name + '=; max-age=0; path=' + path + '; domain=' + domain + ';';
                            document.cookie = name + '=deleted; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=' + path + '; domain=' + domain + ';';
                            cookiesCleaned++;
                        });
                    });
                });
                
                cleanupSteps.push('✅ Cookies: ' + cookiesCleaned + ' Varianten gelöscht');
                console.log('✅ Cookies cleared');
            } catch (e) {
                cleanupSteps.push('❌ Cookies: Fehler - ' + e.message);
                console.error('❌ Cookie cleanup error:', e);
            }
            
            // 2. LOCAL STORAGE LÖSCHEN
            try {
                console.log('💾 Clearing localStorage...');
                const localStorageKeys = getAllStorageKeys(localStorage);
                
                // Spezifische Auth-Keys löschen
                const authKeys = ['auth_token', 'token', 'jwt', 'session', 'user', 'login', 'access_token', 'refresh_token'];
                let localKeysCleared = 0;
                
                authKeys.forEach(key => {
                    if (localStorage.getItem(key)) {
                        localStorage.removeItem(key);
                        localKeysCleared++;
                    }
                });
                
                // Alle Keys mit "auth", "token", "session" im Namen löschen
                localStorageKeys.forEach(key => {
                    if (key && (key.includes('auth') || key.includes('token') || key.includes('session') || key.includes('login'))) {
                        localStorage.removeItem(key);
                        localKeysCleared++;
                    }
                });
                
                // OPTIONAL: Komplettes localStorage löschen (nur wenn gewünscht)
                // localStorage.clear();
                
                cleanupSteps.push('✅ localStorage: ' + localKeysCleared + ' Keys gelöscht');
                console.log('✅ localStorage cleared');
            } catch (e) {
                cleanupSteps.push('❌ localStorage: Fehler - ' + e.message);
                console.error('❌ localStorage cleanup error:', e);
            }
            
            // 3. SESSION STORAGE LÖSCHEN
            try {
                console.log('🗂️ Clearing sessionStorage...');
                const sessionStorageKeys = getAllStorageKeys(sessionStorage);
                
                // Spezifische Auth-Keys löschen
                const authKeys = ['auth_token', 'token', 'jwt', 'session', 'user', 'login', 'access_token', 'refresh_token'];
                let sessionKeysCleared = 0;
                
                authKeys.forEach(key => {
                    if (sessionStorage.getItem(key)) {
                        sessionStorage.removeItem(key);
                        sessionKeysCleared++;
                    }
                });
                
                // Alle Keys mit "auth", "token", "session" im Namen löschen
                sessionStorageKeys.forEach(key => {
                    if (key && (key.includes('auth') || key.includes('token') || key.includes('session') || key.includes('login'))) {
                        sessionStorage.removeItem(key);
                        sessionKeysCleared++;
                    }
                });
                
                // OPTIONAL: Komplettes sessionStorage löschen
                // sessionStorage.clear();
                
                cleanupSteps.push('✅ sessionStorage: ' + sessionKeysCleared + ' Keys gelöscht');
                console.log('✅ sessionStorage cleared');
            } catch (e) {
                cleanupSteps.push('❌ sessionStorage: Fehler - ' + e.message);
                console.error('❌ sessionStorage cleanup error:', e);
            }
            
            // 4. INDEXED DB LÖSCHEN (falls vorhanden)
            try {
                if ('indexedDB' in window) {
                    console.log('🗄️ Checking IndexedDB...');
                    // Hier könnten Sie spezifische IndexedDB-Datenbanken löschen
                    cleanupSteps.push('✅ IndexedDB: Überprüft');
                }
            } catch (e) {
                cleanupSteps.push('⚠️ IndexedDB: ' + e.message);
            }
            
            // 5. CACHE STORAGE LÖSCHEN (Service Worker Cache)
            try {
                if ('caches' in window) {
                    console.log('📦 Clearing Cache Storage...');
                    caches.keys().then(function(names) {
                        for (let name of names) {
                            caches.delete(name);
                        }
                    });
                    cleanupSteps.push('✅ Cache Storage: Geleert');
                }
            } catch (e) {
                cleanupSteps.push('⚠️ Cache Storage: ' + e.message);
            }
            
            // STATUS AKTUALISIEREN
            document.getElementById('cleanup-status').innerHTML = cleanupSteps.join('<br>');
            
            // NACH-CLEANUP STATUS
            setTimeout(() => {
                document.getElementById('cookies-after').textContent = 
                    document.cookie || 'alle gelöscht ✅';
                document.getElementById('localStorage-after').textContent = 
                    getStorageCount(localStorage) + ' (' + getAllStorageKeys(localStorage).join(', ') + ')';
                document.getElementById('sessionStorage-after').textContent = 
                    getStorageCount(sessionStorage) + ' (' + getAllStorageKeys(sessionStorage).join(', ') + ')';
            }, 500);
            
            console.log('✅ Complete logout cleanup finished');
        }
        
        // CLEANUP SOFORT AUSFÜHREN
        completeLogout();
        
        // COUNTDOWN UND AUTOMATISCHE WEITERLEITUNG
        let countdown = 5;
        const countdownElement = document.getElementById('countdown');
        
        const timer = setInterval(() => {
            countdown--;
            countdownElement.textContent = countdown;
            
            if (countdown <= 0) {
                clearInterval(timer);
                
                // NOCHMALS CLEANUP VOR REDIRECT
                completeLogout();
                
                // REDIRECT MIT CACHE-BUSTER
                const timestamp = new Date().getTime();
                const randomId = Math.random().toString(36).substr(2, 9);
                window.location.href = '/login?message=' + 
                    encodeURIComponent('Sie wurden erfolgreich abgemeldet') + 
                    '&t=' + timestamp + '&r=' + randomId;
            }
        }, 1000);
        
        // WINDOW UNLOAD: Final cleanup
        window.addEventListener('beforeunload', function() {
            completeLogout();
        });
        
        // VISIBILITY CHANGE: Cleanup wenn Tab verlassen wird
        document.addEventListener('visibilitychange', function() {
            if (document.hidden) {
                completeLogout();
            }
        });
    </script>
</body>
</html>`

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, logoutHTML)
}

func (fs *FrontendServer) DebugStorageHandler(c *gin.Context) {
	storageHTML := `
<!DOCTYPE html>
<html>
<head>
    <title>Storage Debug</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; }
        .storage-info { 
            background: #f8f9fa; 
            border: 1px solid #dee2e6; 
            padding: 15px; 
            margin: 10px 0; 
            border-radius: 5px; 
        }
        .key { font-weight: bold; color: #007bff; }
        .value { font-family: monospace; background: #e9ecef; padding: 2px 4px; }
    </style>
</head>
<body>
    <h1>🔍 Browser Storage Debug</h1>
    
    <div class="storage-info">
        <h3>🍪 Cookies</h3>
        <div id="cookies"></div>
    </div>
    
    <div class="storage-info">
        <h3>💾 localStorage</h3>
        <div id="localStorage"></div>
    </div>
    
    <div class="storage-info">
        <h3>🗂️ sessionStorage</h3>
        <div id="sessionStorage"></div>
    </div>
    
    <button onclick="clearAllStorage()" style="background: #dc3545; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer;">
        🗑️ Alles löschen
    </button>
    
    <button onclick="location.reload()" style="background: #28a745; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-left: 10px;">
        🔄 Aktualisieren
    </button>

    <script>
        function displayStorage() {
            // Cookies
            let cookiesHtml = '';
            if (document.cookie) {
                document.cookie.split(';').forEach(cookie => {
                    const [key, value] = cookie.trim().split('=');
                    cookiesHtml += '<div><span class="key">' + key + '</span>: <span class="value">' + (value || 'empty') + '</span></div>';
                });
            } else {
                cookiesHtml = '<div>Keine Cookies gefunden</div>';
            }
            document.getElementById('cookies').innerHTML = cookiesHtml;
            
            // localStorage
            let localHtml = '';
            try {
                if (localStorage.length > 0) {
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        const value = localStorage.getItem(key);
                        localHtml += '<div><span class="key">' + key + '</span>: <span class="value">' + (value ? value.substring(0, 100) + (value.length > 100 ? '...' : '') : 'empty') + '</span></div>';
                    }
                } else {
                    localHtml = '<div>localStorage ist leer</div>';
                }
            } catch (e) {
                localHtml = '<div>localStorage Fehler: ' + e.message + '</div>';
            }
            document.getElementById('localStorage').innerHTML = localHtml;
            
            // sessionStorage
            let sessionHtml = '';
            try {
                if (sessionStorage.length > 0) {
                    for (let i = 0; i < sessionStorage.length; i++) {
                        const key = sessionStorage.key(i);
                        const value = sessionStorage.getItem(key);
                        sessionHtml += '<div><span class="key">' + key + '</span>: <span class="value">' + (value ? value.substring(0, 100) + (value.length > 100 ? '...' : '') : 'empty') + '</span></div>';
                    }
                } else {
                    sessionHtml = '<div>sessionStorage ist leer</div>';
                }
            } catch (e) {
                sessionHtml = '<div>sessionStorage Fehler: ' + e.message + '</div>';
            }
            document.getElementById('sessionStorage').innerHTML = sessionHtml;
        }
        
        function clearAllStorage() {
            // Cookies löschen
            document.cookie.split(";").forEach(function(c) { 
                document.cookie = c.replace(/^ +/, "").replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/"); 
            });
            
            // Storage löschen
            localStorage.clear();
            sessionStorage.clear();
            
            alert('Alles gelöscht!');
            displayStorage();
        }
        
        // Initial anzeigen
        displayStorage();
        
        // Auto-refresh alle 2 Sekunden
        setInterval(displayStorage, 2000);
    </script>
</body>
</html>`

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, storageHTML)
}

func (fs *FrontendServer) clearAllAuthCookies(c *gin.Context) {
	log.Printf("🗑️ Aggressively clearing all auth cookies")

	cookieVariants := []struct {
		name   string
		path   string
		domain string
	}{
		{"auth_token", "/", ""},
		{"auth_token", "", ""},
		{"auth_token", "/", "localhost"},
		{"auth_token", "/", ".localhost"},
		{"session", "/", ""},
		{"token", "/", ""},
		{"jwt", "/", ""},
		{"user", "/", ""},
		{"login", "/", ""},
	}

	for _, variant := range cookieVariants {
		// Methode 1: Leerer Wert + Vergangenheit
		c.SetCookie(variant.name, "", -86400, variant.path, variant.domain, false, true)
		// Methode 2: "deleted" Wert + Vergangenheit
		c.SetCookie(variant.name, "deleted", -86400, variant.path, variant.domain, false, true)
		// Methode 3: Aktuelles Datum aber expired
		c.SetCookie(variant.name, "", -1, variant.path, variant.domain, false, true)

		log.Printf("🗑️ Deleted cookie variant: %s (path: %s, domain: %s)",
			variant.name, variant.path, variant.domain)
	}
}

func (fs *FrontendServer) invalidateTokenBackend(token string) {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("POST", fs.apiURL+"/auth/logout", nil)
	if err != nil {
		log.Printf("⚠️ Failed to create logout request: %v", err)
		return
	}

	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("⚠️ Failed to invalidate token: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		log.Printf("✅ Token successfully invalidated on backend")
	} else {
		log.Printf("⚠️ Backend logout returned status: %d", resp.StatusCode)
	}
}

func (fs *FrontendServer) DebugRoutesHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"current_path": c.Request.URL.Path,
		"method":       c.Request.Method,
		"middlewares":  "check console logs",
		"user_agent":   c.GetHeader("User-Agent"),
		"all_headers":  c.Request.Header,
		"cookies":      c.Request.Cookies(),
		"message":      "Check server logs for middleware execution order",
	})
}

// Admin middleware für Frontend
func (fs *FrontendServer) adminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Printf("👑 Admin middleware: Checking admin rights for %s %s", c.Request.Method, c.Request.URL.Path)

		// Employee aus Context holen (gesetzt von authMiddleware)
		employeeInterface, exists := c.Get("employee")
		if !exists {
			log.Printf("❌ No employee in context for admin check")
			c.HTML(http.StatusForbidden, "error.html", gin.H{
				"Title":      "Authentifizierungsfehler",
				"Message":    "Sitzungsdaten nicht gefunden. Bitte melden Sie sich erneut an.",
				"APIBaseURL": fs.apiURL,
			})
			c.Abort()
			return
		}

		employee, ok := employeeInterface.(Employee)
		if !ok {
			log.Printf("❌ Invalid employee object in context")
			c.HTML(http.StatusForbidden, "error.html", gin.H{
				"Title":      "Authentifizierungsfehler",
				"Message":    "Ungültige Sitzungsdaten. Bitte melden Sie sich erneut an.",
				"APIBaseURL": fs.apiURL,
			})
			c.Abort()
			return
		}

		if !employee.IsAdmin {
			log.Printf("❌ User %s %s is not admin", employee.FirstName, employee.LastName)
			c.HTML(http.StatusForbidden, "error.html", gin.H{
				"Title":      "Zugriff verweigert",
				"Message":    "Sie haben keine Berechtigung für diese Aktion. Nur Administratoren können auf diese Seite zugreifen.",
				"APIBaseURL": fs.apiURL,
			})
			c.Abort()
			return
		}

		log.Printf("✅ Admin check passed for %s %s", employee.FirstName, employee.LastName)
		c.Next()
	}
}

// Enhanced API Client with Authentication
func (c *APIClient) makeAuthenticatedRequest(method, endpoint string, data interface{}) (*http.Response, error) {
	var body io.Reader
	if data != nil {
		jsonData, err := json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("JSON serialization failed: %v", err)
		}
		body = strings.NewReader(string(jsonData))
	}

	req, err := http.NewRequest(method, c.baseURL+endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("Failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Add authentication header if token exists
	// This would need to be passed from the frontend context
	// For now, we'll handle authentication at the proxy level

	return c.client.Do(req)
}

// Enhanced Employee Creation Handler with Password Management
func (fs *FrontendServer) CreateEmployeePostHandler(c *gin.Context) {
	apiClient := NewAPIClient(fs.apiURL)

	firstName := c.PostForm("first_name")
	lastName := c.PostForm("last_name")
	email := c.PostForm("email")
	department := c.PostForm("department")
	isAdmin := c.PostForm("is_admin") == "on"
	isActive := c.PostForm("is_active") != "off" // Default to active

	if firstName == "" || lastName == "" || email == "" {
		c.Redirect(http.StatusSeeOther, "/employees/create?error="+url.QueryEscape("Alle Pflichtfelder müssen ausgefüllt werden"))
		return
	}

	newEmployee := Employee{
		FirstName:  firstName,
		LastName:   lastName,
		Email:      email,
		Department: department,
		IsAdmin:    isAdmin,
		IsActive:   isActive,
	}

	// Forward auth token from request
	token := c.GetHeader("Authorization")
	if token == "" {
		if cookie, err := c.Cookie("auth_token"); err == nil {
			token = "Bearer " + cookie
		}
	}

	err := apiClient.CreateEmployeeWithAuth(newEmployee, token)
	if err != nil {
		log.Printf("Error creating employee: %v", err)
		errorMsg := "Fehler beim Erstellen des Mitarbeiters"

		if strings.Contains(err.Error(), "Duplicate entry") && strings.Contains(err.Error(), "email") {
			errorMsg = fmt.Sprintf("Die E-Mail-Adresse '%s' ist bereits vergeben", email)
		}

		c.Redirect(http.StatusSeeOther, "/employees/create?error="+url.QueryEscape(errorMsg))
		return
	}

	successMsg := fmt.Sprintf("Mitarbeiter '%s %s' wurde erfolgreich erstellt", firstName, lastName)
	if isAdmin {
		successMsg += ". Ein temporäres Passwort wurde generiert."
	}
	c.Redirect(http.StatusSeeOther, "/employees?success="+url.QueryEscape(successMsg))
}

// Enhanced Employee Update Handler
func (fs *FrontendServer) EditEmployeePostHandler(c *gin.Context) {
	employeeID := c.Param("id")
	apiClient := NewAPIClient(fs.apiURL)

	// TOKEN EXTRAHIEREN UND SETZEN
	token := fs.extractToken(c)
	if token != "" {
		apiClient.SetToken(token)
	} else {
		log.Printf("❌ No token found in EditEmployeePostHandler")
		c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Authentifizierung erforderlich"))
		return
	}

	firstName := c.PostForm("first_name")
	lastName := c.PostForm("last_name")
	email := c.PostForm("email")
	department := c.PostForm("department")

	// *** HIER IST DAS PROBLEM UND DIE LÖSUNG ***
	// Checkboxes senden nur Werte wenn sie checked sind!
	// Wenn unchecked → kein Wert im POST → wird als false interpretiert

	// RICHTIGE CHECKBOX-BEHANDLUNG:
	isAdmin := c.PostForm("is_admin") == "on" // ✅ Das funktioniert

	// *** PROBLEM: is_active wird nicht richtig behandelt ***
	// FALSCH (bisherige Version):
	// isActive := c.PostForm("is_active") != "off"  // ❌ Das ist das Problem!

	// RICHTIG:
	isActive := c.PostForm("is_active") == "on" // ✅ Das ist die Lösung!

	log.Printf("🔍 Form data received:")
	log.Printf("   first_name: %s", firstName)
	log.Printf("   last_name: %s", lastName)
	log.Printf("   email: %s", email)
	log.Printf("   department: %s", department)
	log.Printf("   is_admin: %s → %t", c.PostForm("is_admin"), isAdmin)
	log.Printf("   is_active: %s → %t", c.PostForm("is_active"), isActive)

	if firstName == "" || lastName == "" || email == "" {
		c.Redirect(http.StatusSeeOther, fmt.Sprintf("/employees/%s/edit?error=%s", employeeID, url.QueryEscape("Alle Pflichtfelder müssen ausgefüllt werden")))
		return
	}

	updatedEmployee := EmployeeUpdateRequest{
		FirstName:  firstName,
		LastName:   lastName,
		Email:      email,
		Department: department,
		IsAdmin:    isAdmin,
		IsActive:   isActive, // ✅ Jetzt wird false korrekt übertragen
	}

	log.Printf("🔄 Updating employee with: %+v", updatedEmployee)

	err := apiClient.UpdateEmployeeWithAuth(employeeID, updatedEmployee, token)
	if err != nil {
		log.Printf("Error updating employee: %v", err)
		c.Redirect(http.StatusSeeOther, fmt.Sprintf("/employees/%s/edit?error=%s", employeeID, url.QueryEscape("Fehler beim Aktualisieren des Mitarbeiters")))
		return
	}

	successMsg := fmt.Sprintf("Mitarbeiter '%s %s' wurde erfolgreich aktualisiert", firstName, lastName)
	c.Redirect(http.StatusSeeOther, "/employees?success="+url.QueryEscape(successMsg))
}

// API Client methods with authentication
func (c *APIClient) CreateEmployeeWithAuth(employee Employee, token string) error {
	jsonData, err := json.Marshal(employee)
	if err != nil {
		return fmt.Errorf("JSON serialization failed: %v", err)
	}

	req, err := http.NewRequest("POST", c.baseURL+"/employees", strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("Failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (c *APIClient) UpdateEmployeeWithAuth(id string, employee EmployeeUpdateRequest, token string) error {
	jsonData, err := json.Marshal(employee)
	if err != nil {
		return fmt.Errorf("JSON serialization failed: %v", err)
	}

	req, err := http.NewRequest("PUT", c.baseURL+"/employees/"+id, strings.NewReader(string(jsonData)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Enhanced API Proxy Handler with Authentication
func (fs *FrontendServer) APIProxyHandler(c *gin.Context) {
	path := c.Param("path")
	method := c.Request.Method

	// Forward request to backend API
	targetURL := fs.apiURL + "/" + strings.TrimPrefix(path, "/")

	// Create new request
	req, err := http.NewRequest(method, targetURL, c.Request.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	// Copy headers
	for key, values := range c.Request.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// Add authentication header if available
	token := c.GetHeader("Authorization")
	if token == "" {
		if cookie, err := c.Cookie("auth_token"); err == nil {
			req.Header.Set("Authorization", "Bearer "+cookie)
		}
	}

	// Execute request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "API request failed"})
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			c.Header(key, value)
		}
	}

	// Copy response status and body
	c.Status(resp.StatusCode)

	// Stream response body
	buffer := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(buffer)
		if n > 0 {
			c.Writer.Write(buffer[:n])
		}
		if err != nil {
			break
		}
	}
}

func NewAPIClient(baseURL string) *APIClient {
	return &APIClient{
		baseURL: baseURL,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *APIClient) GetAsset(id string) (Asset, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/assets/"+id, nil)
	if err != nil {
		return Asset{}, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", c.token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return Asset{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Asset{}, fmt.Errorf("API error %d", resp.StatusCode)
	}

	var asset Asset
	if err := json.NewDecoder(resp.Body).Decode(&asset); err != nil {
		return Asset{}, err
	}
	return asset, nil
}

func (c *APIClient) GetAssets() ([]Asset, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/assets", nil)
	if err != nil {
		return nil, err
	}

	// Token hinzufügen wenn vorhanden
	if c.token != "" {
		req.Header.Set("Authorization", c.token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error %d", resp.StatusCode)
	}

	var assets []Asset
	if err := json.NewDecoder(resp.Body).Decode(&assets); err != nil {
		return nil, err
	}
	return assets, nil
}

func (c *APIClient) SetToken(token string) {
	c.token = token
}

func (c *APIClient) GetEmployees() ([]Employee, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/employees", nil)
	if err != nil {
		return nil, err
	}

	// Token hinzufügen wenn vorhanden
	if c.token != "" {
		req.Header.Set("Authorization", c.token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error %d", resp.StatusCode)
	}

	var employees []Employee
	if err := json.NewDecoder(resp.Body).Decode(&employees); err != nil {
		return nil, err
	}
	return employees, nil
}

// Route Handlers
func (fs *FrontendServer) IndexHandler(c *gin.Context) {
	apiClient := NewAPIClient(fs.apiURL)

	// Token extrahieren und setzen
	token := fs.extractToken(c)
	if token != "" {
		apiClient.SetToken(token)
	}
	// Get current user from context
	employee, exists := c.Get("employee")
	if !exists {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}

	emp := employee.(Employee)
	assets, err := apiClient.GetAssets()
	if err != nil {
		log.Printf("Error fetching assets: %v", err)
		assets = []Asset{}
	}

	employees, err := apiClient.GetEmployees()
	if err != nil {
		log.Printf("Error fetching employees: %v", err)
		employees = []Employee{}
	}

	data := PageData{
		Title:       "Asset Management Dashboard",
		APIBaseURL:  fs.apiURL,
		Assets:      assets,
		Employees:   employees,
		CurrentUser: emp,
		Template:    "index-content",
		Version:     Version,
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := fs.templates.ExecuteTemplate(c.Writer, "index.html", data); err != nil {
		log.Printf("Template error: %v", err)
		c.String(http.StatusInternalServerError, "Template error: %v", err)
	}
}

func (fs *FrontendServer) extractToken(c *gin.Context) string {
	// 1. Authorization Header
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		return authHeader
	}

	// 2. Cookie
	if cookie, err := c.Cookie("auth_token"); err == nil && cookie != "" {
		return "Bearer " + cookie
	}

	// 3. Query parameter (fallback)
	if queryToken := c.Query("token"); queryToken != "" {
		return "Bearer " + queryToken
	}

	return ""
}

func (fs *FrontendServer) AssetsHandler(c *gin.Context) {
	apiClient := NewAPIClient(fs.apiURL)

	// Token extrahieren und setzen
	token := fs.extractToken(c)
	if token != "" {
		apiClient.SetToken(token)
	}

	// Get current user from context
	employee, exists := c.Get("employee")
	if !exists {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}

	emp := employee.(Employee)

	assets, err := apiClient.GetAssets()
	if err != nil {
		log.Printf("Error fetching assets: %v", err)
		c.String(http.StatusInternalServerError, "Error fetching assets: %v", err)
		return
	}

	employees, err := apiClient.GetEmployees()
	if err != nil {
		log.Printf("Error fetching employees: %v", err)
		employees = []Employee{}
	}

	data := PageData{
		Title:       "Assets",
		APIBaseURL:  fs.apiURL,
		Assets:      assets,
		Employees:   employees,
		Template:    "assets-content",
		CurrentUser: emp,
		Version:     Version,
	}

	c.Header("Content-Type", "text-html; charset=utf-8")
	if err := fs.templates.ExecuteTemplate(c.Writer, "assets.html", data); err != nil {
		log.Printf("Template error: %v", err)
		c.String(http.StatusInternalServerError, "Template error: %v", err)
	}
}

func (fs *FrontendServer) EmployeesHandler(c *gin.Context) {
	apiClient := NewAPIClient(fs.apiURL)

	// Token extrahieren und setzen
	token := fs.extractToken(c)
	if token != "" {
		apiClient.SetToken(token)
	}

	// Get current user from context
	employee, exists := c.Get("employee")
	if !exists {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}

	emp := employee.(Employee)

	employees, err := apiClient.GetEmployees()
	if err != nil {
		log.Printf("Error fetching employees: %v", err)
		c.String(http.StatusInternalServerError, "Error fetching employees: %v", err)
		return
	}

	assets, err := apiClient.GetAssets()
	if err != nil {
		log.Printf("Error fetching assets: %v", err)
		assets = []Asset{}
	}

	data := PageData{
		Title:       "Mitarbeiter",
		APIBaseURL:  fs.apiURL,
		Assets:      assets,
		Employees:   employees,
		CurrentUser: emp,
		Template:    "employees-content",
		Version:     Version,
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := fs.templates.ExecuteTemplate(c.Writer, "employees.html", data); err != nil {
		log.Printf("Template error: %v", err)
		c.String(http.StatusInternalServerError, "Template error: %v", err)
	}
}

// CreateAssetHandler - Zeigt das Formular zum Erstellen neuer Assets
func (fs *FrontendServer) CreateAssetHandler(c *gin.Context) {
	apiClient := NewAPIClient(fs.apiURL)

	// Get current user from context
	employee, exists := c.Get("employee")
	if !exists {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}

	emp := employee.(Employee)

	employees, err := apiClient.GetEmployees()
	if err != nil {
		log.Printf("Error fetching employees: %v", err)
		employees = []Employee{}
	}

	data := PageData{
		Title:       "Neues Asset erstellen",
		APIBaseURL:  fs.apiURL,
		Employees:   employees,
		Template:    "asset-create-content",
		CurrentUser: emp,
		Version:     Version,
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := fs.templates.ExecuteTemplate(c.Writer, "create_asset.html", data); err != nil {
		log.Printf("Template error: %v", err)
		c.String(http.StatusInternalServerError, "Template error: %v", err)
	}
}

func (fs *FrontendServer) CreateAssetPostHandler(c *gin.Context) {
	apiClient := NewAPIClient(fs.apiURL)

	// TOKEN SETZEN
	token := fs.extractToken(c)
	if token != "" {
		apiClient.SetToken(token)
	} else {
		log.Printf("❌ No token found in CreateAssetPostHandler")
		c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Authentifizierung erforderlich"))
		return
	}

	// Parse form data
	name := c.PostForm("name")
	deviceType := c.PostForm("device_type")
	serialNumber := c.PostForm("serial_number")
	priceStr := c.PostForm("price")
	purchaseDateStr := c.PostForm("purchase_date")
	status := c.PostForm("status")
	currentUserStr := c.PostForm("current_user")

	// Validate required fields
	if name == "" || deviceType == "" || serialNumber == "" || priceStr == "" || purchaseDateStr == "" {
		c.Redirect(http.StatusSeeOther, "/assets/create?error="+url.QueryEscape("Alle Pflichtfelder müssen ausgefüllt werden"))
		return
	}

	// Parse price
	price, err := strconv.ParseFloat(priceStr, 64)
	if err != nil {
		c.Redirect(http.StatusSeeOther, "/assets/create?error="+url.QueryEscape("Ungültiger Preis"))
		return
	}

	// Parse purchase date
	purchaseDate, err := time.Parse("2006-01-02", purchaseDateStr)
	if err != nil {
		c.Redirect(http.StatusSeeOther, "/assets/create?error="+url.QueryEscape("Ungültiges Datum"))
		return
	}

	// Parse current user (optional)
	var currentUser *uint
	if currentUserStr != "" && currentUserStr != "0" {
		userID, err := strconv.ParseUint(currentUserStr, 10, 32)
		if err == nil {
			userId := uint(userID)
			currentUser = &userId
		}
	}

	// Create asset object
	newAsset := Asset{
		Name:         name,
		DeviceType:   deviceType,
		SerialNumber: serialNumber,
		PurchaseDate: purchaseDate,
		Price:        price,
		Status:       status,
		CurrentUser:  currentUser,
	}

	// Send to API with improved error handling
	err = apiClient.CreateAsset(newAsset)
	if err != nil {
		log.Printf("Error creating asset: %v", err)

		// Parse different types of errors
		errorMsg := "Unbekannter Fehler beim Erstellen des Assets"

		if strings.Contains(err.Error(), "401") {
			errorMsg = "Authentifizierung fehlgeschlagen. Bitte melden Sie sich erneut an."
		} else if strings.Contains(err.Error(), "Duplicate entry") && strings.Contains(err.Error(), "serial_number") {
			errorMsg = fmt.Sprintf("Die Seriennummer '%s' ist bereits vergeben. Bitte verwenden Sie eine andere Seriennummer.", serialNumber)
		} else if strings.Contains(err.Error(), "API error 400") {
			errorMsg = "Ungültige Daten. Bitte prüfen Sie Ihre Eingaben."
		} else if strings.Contains(err.Error(), "API error 500") {
			errorMsg = "Server-Fehler. Bitte versuchen Sie es später erneut."
		} else if strings.Contains(err.Error(), "connection") {
			errorMsg = "Verbindungsfehler zum Backend. Bitte prüfen Sie die Netzwerkverbindung."
		} else {
			errorMsg = fmt.Sprintf("Fehler: %s", err.Error())
		}

		c.Redirect(http.StatusSeeOther, "/assets/create?error="+url.QueryEscape(errorMsg))
		return
	}

	// Success redirect
	successMsg := fmt.Sprintf("Asset '%s' (%s) wurde erfolgreich erstellt", name, serialNumber)
	c.Redirect(http.StatusSeeOther, "/assets?success="+url.QueryEscape(successMsg))
}

func (c *APIClient) CreateAsset(asset Asset) error {
	jsonData, err := json.Marshal(asset)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", c.baseURL+"/assets", strings.NewReader(string(jsonData)))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", c.token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (fs *FrontendServer) CreateEmployeeHandler(c *gin.Context) {
	// Get current user from context
	employee, exists := c.Get("employee")
	if !exists {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}

	emp := employee.(Employee)
	data := PageData{
		Title:       "Neuen Mitarbeiter erstellen",
		APIBaseURL:  fs.apiURL,
		CurrentUser: emp,
		Template:    "employee-create-content",
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := fs.templates.ExecuteTemplate(c.Writer, "create_employee.html", data); err != nil {
		log.Printf("Template error: %v", err)
		c.String(http.StatusInternalServerError, "Template error: %v", err)
	}
}

func (fs *FrontendServer) EditEmployeeHandler(c *gin.Context) {
	employeeID := c.Param("id")
	apiClient := NewAPIClient(fs.apiURL)

	// TOKEN EXTRAHIEREN UND SETZEN - DAS WAR DAS PROBLEM!
	token := fs.extractToken(c)
	if token != "" {
		apiClient.SetToken(token)
		log.Printf("🔑 Token set for EditEmployeeHandler: %s", token[:20]+"...")
	} else {
		log.Printf("❌ No token found in EditEmployeeHandler")
	}

	// Get current user from context
	employeea, exists := c.Get("employee")
	if !exists {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}

	emp := employeea.(Employee)

	employee, err := apiClient.GetEmployee(employeeID)
	if err != nil {
		log.Printf("Error fetching employee %s: %v", employeeID, err)
		c.String(http.StatusNotFound, "Employee not found: %v", err)
		return
	}

	data := PageData{
		Title:       fmt.Sprintf("Mitarbeiter bearbeiten - %s %s", employee.FirstName, employee.LastName),
		Employee:    &employee,    // Einzelner Employee (erweitere PageData um dieses Feld)
		Employees:   []Employee{}, // Leeres Array für Template-Kompatibilität
		Assets:      []Asset{},    // Leeres Array für Template-Kompatibilität
		APIBaseURL:  fs.apiURL,
		Template:    "employee-edit-content",
		CurrentUser: emp,
		Version:     Version,
	}

	// data := struct {
	// 	Title       string
	// 	Employee    []Employee
	// 	APIBaseURL  string
	// 	Assets      []Asset
	// 	Template    string
	// 	CurrentUser Employee
	// }{
	// 	Title:       fmt.Sprintf("Mitarbeiter bearbeiten - %s %s", employee.FirstName, employee.LastName),
	// 	Employee:    &employee,
	// 	APIBaseURL:  fs.apiURL,
	// 	Template:    "employee-edit-content",
	// 	CurrentUser: emp,
	// }

	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := fs.templates.ExecuteTemplate(c.Writer, "edit_employee.html", data); err != nil {
		log.Printf("Template error: %v", err)
		c.String(http.StatusInternalServerError, "Template error: %v", err)
	}
}

// AUCH ALLE ANDEREN EDIT/CREATE/DELETE HANDLER KORRIGIEREN:

func (fs *FrontendServer) EditAssetHandler(c *gin.Context) {
	assetID := c.Param("id")
	apiClient := NewAPIClient(fs.apiURL)

	// TOKEN SETZEN
	token := fs.extractToken(c)
	if token != "" {
		apiClient.SetToken(token)
	}

	asset, err := apiClient.GetAsset(assetID)
	if err != nil {
		log.Printf("Error fetching asset %s: %v", assetID, err)
		c.String(http.StatusNotFound, "Asset not found: %v", err)
		return
	}
	// Get current user from context
	employee, exists := c.Get("employee")
	if !exists {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}

	emp := employee.(Employee)

	employees, err := apiClient.GetEmployees()
	if err != nil {
		log.Printf("Error fetching employees: %v", err)
		employees = []Employee{}
	}

	data := struct {
		Title       string
		Asset       Asset
		Assets      []Asset
		Employees   []Employee
		APIBaseURL  string
		Template    string
		CurrentUser Employee
		Version     string
	}{
		Title:       fmt.Sprintf("Asset bearbeiten - %s", asset.DeviceType),
		Asset:       asset,
		Assets:      []Asset{asset},
		Employees:   employees,
		APIBaseURL:  fs.apiURL,
		CurrentUser: emp,
		Template:    "asset-edit-content",
		Version:     Version,
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := fs.templates.ExecuteTemplate(c.Writer, "edit_asset.html", data); err != nil {
		log.Printf("Template error: %v", err)
		c.String(http.StatusInternalServerError, "Template error: %v", err)
	}
}

func (fs *FrontendServer) AssetHistoryHandler(c *gin.Context) {
	assetID := c.Param("id")
	apiClient := NewAPIClient(fs.apiURL)

	// TOKEN SETZEN
	token := fs.extractToken(c)
	if token != "" {
		apiClient.SetToken(token)
	}

	// Get current user from context
	employee, exists := c.Get("employee")
	if !exists {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}

	emp := employee.(Employee)

	// Get asset details
	asset, err := apiClient.GetAsset(assetID)
	if err != nil {
		log.Printf("Error fetching asset %s: %v", assetID, err)
		c.String(http.StatusNotFound, "Asset not found: %v", err)
		return
	}

	// Get asset history
	history, err := apiClient.GetAssetHistory(assetID)
	if err != nil {
		log.Printf("Error fetching asset history: %v", err)
		history = []AssetHistory{}
	}

	// Get employees for dropdowns
	employees, err := apiClient.GetEmployees()
	if err != nil {
		log.Printf("Error fetching employees: %v", err)
		employees = []Employee{}
	}

	data := struct {
		Title       string
		Asset       Asset
		Assets      []Asset
		History     []AssetHistory
		Employees   []Employee
		APIBaseURL  string
		Template    string
		CurrentUser Employee
		Version     string
	}{
		Title:       fmt.Sprintf("Asset History - %s", asset.DeviceType),
		Asset:       asset,
		Assets:      []Asset{asset},
		History:     history,
		Employees:   employees,
		APIBaseURL:  fs.apiURL,
		Template:    "assets-history-content",
		CurrentUser: emp,
		Version:     Version,
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := fs.templates.ExecuteTemplate(c.Writer, "asset_history.html", data); err != nil {
		log.Printf("Template error: %v", err)
		c.String(http.StatusInternalServerError, "Template error: %v", err)
	}
}

func (fs *FrontendServer) AssetManagementHandler(c *gin.Context) {
	assetID := c.Param("id")
	apiClient := NewAPIClient(fs.apiURL)

	// TOKEN SETZEN
	token := fs.extractToken(c)
	if token != "" {
		apiClient.SetToken(token)
	}

	asset, err := apiClient.GetAsset(assetID)
	if err != nil {
		log.Printf("Error fetching asset %s: %v", assetID, err)
		c.String(http.StatusNotFound, "Asset not found: %v", err)
		return
	}
	// Get current user from context
	employee, exists := c.Get("employee")
	if !exists {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}

	emp := employee.(Employee)
	employees, err := apiClient.GetEmployees()
	if err != nil {
		log.Printf("Error fetching employees: %v", err)
		employees = []Employee{}
	}

	data := struct {
		Title       string
		Asset       Asset
		Assets      []Asset
		Employees   []Employee
		APIBaseURL  string
		Template    string
		CurrentUser Employee
		Version     string
	}{
		Title:       fmt.Sprintf("Asset verwalten - %s", asset.DeviceType),
		Asset:       asset,
		Assets:      []Asset{asset},
		Employees:   employees,
		APIBaseURL:  fs.apiURL,
		CurrentUser: emp,
		Template:    "asset-manage-content",
		Version:     Version,
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := fs.templates.ExecuteTemplate(c.Writer, "manage_asset.html", data); err != nil {
		log.Printf("Template error: %v", err)
		c.String(http.StatusInternalServerError, "Template error: %v", err)
	}
}

// ERWEITERE AUCH GetAssetHistory Methode im APIClient:
func (c *APIClient) GetAssetHistory(id string) ([]AssetHistory, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/assets/"+id+"/history", nil)
	if err != nil {
		return nil, err
	}

	// Token hinzufügen wenn vorhanden
	if c.token != "" {
		req.Header.Set("Authorization", c.token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error %d", resp.StatusCode)
	}

	var history []AssetHistory
	if err := json.NewDecoder(resp.Body).Decode(&history); err != nil {
		return nil, err
	}
	return history, nil
}

// ALTERNATIVE: Nutze das Token direkt aus dem Context wenn vorhanden
func (fs *FrontendServer) EditEmployeeHandlerV2(c *gin.Context) {
	employeeID := c.Param("id")
	apiClient := NewAPIClient(fs.apiURL)

	// BESSER: Token aus Context holen (gesetzt von authMiddleware)
	if tokenInterface, exists := c.Get("auth_token"); exists {
		if token, ok := tokenInterface.(string); ok {
			apiClient.SetToken(token)
			log.Printf("🔑 Using token from context: %s", token[:20]+"...")
		}
	} else {
		// Fallback: Token extrahieren
		token := fs.extractToken(c)
		if token != "" {
			apiClient.SetToken(token)
			log.Printf("🔑 Using extracted token: %s", token[:20]+"...")
		}
	}

	employee, err := apiClient.GetEmployee(employeeID)
	if err != nil {
		log.Printf("❌ Error fetching employee %s: %v", employeeID, err)
		c.String(http.StatusNotFound, "Employee not found: %v", err)
		return
	}

	log.Printf("✅ Successfully fetched employee: %s %s", employee.FirstName, employee.LastName)

	data := struct {
		Title      string
		Employee   Employee
		APIBaseURL string
	}{
		Title:      fmt.Sprintf("Mitarbeiter bearbeiten - %s %s", employee.FirstName, employee.LastName),
		Employee:   employee,
		APIBaseURL: fs.apiURL,
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := fs.templates.ExecuteTemplate(c.Writer, "edit_employee.html", data); err != nil {
		log.Printf("Template error: %v", err)
		c.String(http.StatusInternalServerError, "Template error: %v", err)
	}
}

// DEBUGGING: Handler zum Testen der Token-Extraktion
func (fs *FrontendServer) DebugTokenHandler(c *gin.Context) {
	log.Printf("🔍 Debug Token Handler called")

	// Test alle Token-Quellen
	authHeader := c.GetHeader("Authorization")
	log.Printf("📋 Authorization Header: '%s'", authHeader)

	cookie, err := c.Cookie("auth_token")
	log.Printf("🍪 Cookie auth_token: '%s' (error: %v)", cookie, err)

	queryToken := c.Query("token")
	log.Printf("🔗 Query token: '%s'", queryToken)

	// Test Context
	if tokenInterface, exists := c.Get("auth_token"); exists {
		log.Printf("📦 Context token: '%v'", tokenInterface)
	} else {
		log.Printf("📦 No token in context")
	}

	// Test Employee in Context
	if employeeInterface, exists := c.Get("employee"); exists {
		if employee, ok := employeeInterface.(Employee); ok {
			log.Printf("👤 Employee in context: %s %s", employee.FirstName, employee.LastName)
		}
	}

	token := fs.extractToken(c)
	log.Printf("🎯 Extracted token: '%s'", token)

	c.JSON(http.StatusOK, gin.H{
		"auth_header":          authHeader,
		"cookie":               cookie,
		"query":                queryToken,
		"extracted":            token,
		"has_context_token":    c.Keys["auth_token"] != nil,
		"has_context_employee": c.Keys["employee"] != nil,
	})
}

func (fs *FrontendServer) DeleteEmployeeHandler(c *gin.Context) {
	employeeID := c.Param("id")
	apiClient := NewAPIClient(fs.apiURL)

	err := apiClient.DeleteEmployee(employeeID)
	if err != nil {
		log.Printf("Error deleting employee: %v", err)
		errorMsg := "Fehler beim Löschen des Mitarbeiters"
		if strings.Contains(err.Error(), "assigned assets") {
			errorMsg = "Mitarbeiter kann nicht gelöscht werden, da noch Assets zugewiesen sind"
		}
		c.Redirect(http.StatusSeeOther, "/employees?error="+url.QueryEscape(errorMsg))
		return
	}

	c.Redirect(http.StatusSeeOther, "/employees?success="+url.QueryEscape("Mitarbeiter wurde erfolgreich gelöscht"))
}

func (fs *FrontendServer) EditAssetPostHandler(c *gin.Context) {
	assetID := c.Param("id")
	apiClient := NewAPIClient(fs.apiURL)

	// *** KRITISCH: TOKEN EXTRAHIEREN UND SETZEN ***
	token := fs.extractToken(c)
	if token != "" {
		apiClient.SetToken(token)
		log.Printf("🔑 Token set for EditAssetPostHandler: %s", token[:20]+"...")
	} else {
		log.Printf("❌ No token found in EditAssetPostHandler")
		c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Authentifizierung erforderlich"))
		return
	}

	// Parse form data - name hinzufügen!
	name := c.PostForm("name")
	deviceType := c.PostForm("device_type")
	serialNumber := c.PostForm("serial_number")
	priceStr := c.PostForm("price")
	purchaseDateStr := c.PostForm("purchase_date")
	status := c.PostForm("status")
	currentUserStr := c.PostForm("current_user")

	log.Printf("📝 Form data received: name=%s, type=%s, serial=%s, price=%s",
		name, deviceType, serialNumber, priceStr)

	// Validate required fields
	if name == "" || deviceType == "" || serialNumber == "" || priceStr == "" || purchaseDateStr == "" {
		c.Redirect(http.StatusSeeOther, fmt.Sprintf("/assets/%s/edit?error=%s", assetID, url.QueryEscape("Alle Pflichtfelder müssen ausgefüllt werden")))
		return
	}

	price, err := strconv.ParseFloat(priceStr, 64)
	if err != nil {
		c.Redirect(http.StatusSeeOther, fmt.Sprintf("/assets/%s/edit?error=%s", assetID, url.QueryEscape("Ungültiger Preis")))
		return
	}

	purchaseDate, err := time.Parse("2006-01-02", purchaseDateStr)
	if err != nil {
		c.Redirect(http.StatusSeeOther, fmt.Sprintf("/assets/%s/edit?error=%s", assetID, url.QueryEscape("Ungültiges Datum")))
		return
	}

	var currentUser *uint
	if currentUserStr != "" && currentUserStr != "0" {
		userID, err := strconv.ParseUint(currentUserStr, 10, 32)
		if err == nil {
			userId := uint(userID)
			currentUser = &userId
		}
	}

	// Create updated asset object
	updatedAsset := Asset{
		Name:         name,
		DeviceType:   deviceType,
		SerialNumber: serialNumber,
		PurchaseDate: purchaseDate,
		Price:        price,
		Status:       status,
		CurrentUser:  currentUser,
	}

	log.Printf("🔄 Updating asset %s with data: %+v", assetID, updatedAsset)

	err = apiClient.UpdateAsset(assetID, updatedAsset)
	if err != nil {
		log.Printf("❌ Error updating asset: %v", err)

		// Bessere Fehlerbehandlung
		errorMsg := "Fehler beim Aktualisieren des Assets"
		if strings.Contains(err.Error(), "401") {
			errorMsg = "Authentifizierung fehlgeschlagen. Bitte melden Sie sich erneut an."
		} else if strings.Contains(err.Error(), "400") {
			errorMsg = "Ungültige Daten. Bitte prüfen Sie Ihre Eingaben."
		} else if strings.Contains(err.Error(), "403") {
			errorMsg = "Keine Berechtigung für diese Aktion."
		} else if strings.Contains(err.Error(), "404") {
			errorMsg = "Asset nicht gefunden."
		} else if strings.Contains(err.Error(), "Duplicate entry") {
			errorMsg = "Seriennummer bereits vergeben."
		}

		c.Redirect(http.StatusSeeOther, fmt.Sprintf("/assets/%s/edit?error=%s", assetID, url.QueryEscape(errorMsg)))
		return
	}

	log.Printf("✅ Asset %s updated successfully", assetID)
	successMsg := fmt.Sprintf("Asset '%s' wurde erfolgreich aktualisiert", name)
	c.Redirect(http.StatusSeeOther, "/assets?success="+url.QueryEscape(successMsg))
}

func (fs *FrontendServer) DeleteAssetHandler(c *gin.Context) {
	assetID := c.Param("id")
	apiClient := NewAPIClient(fs.apiURL)

	// TOKEN SETZEN
	token := fs.extractToken(c)
	if token != "" {
		apiClient.SetToken(token)
	} else {
		log.Printf("❌ No token found in DeleteAssetHandler")
		c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Authentifizierung erforderlich"))
		return
	}

	err := apiClient.DeleteAsset(assetID)
	if err != nil {
		log.Printf("Error deleting asset: %v", err)
		errorMsg := "Fehler beim Löschen des Assets"
		if strings.Contains(err.Error(), "401") {
			errorMsg = "Authentifizierung fehlgeschlagen"
		} else if strings.Contains(err.Error(), "currently assigned") {
			errorMsg = "Asset kann nicht gelöscht werden, da es noch zugewiesen ist"
		}
		c.Redirect(http.StatusSeeOther, "/assets?error="+url.QueryEscape(errorMsg))
		return
	}

	c.Redirect(http.StatusSeeOther, "/assets?success="+url.QueryEscape("Asset wurde erfolgreich gelöscht"))
}

// API Client-Erweiterungen
func (c *APIClient) CreateEmployee(employee Employee) error {
	jsonData, err := json.Marshal(employee)
	if err != nil {
		return fmt.Errorf("JSON-Serialisierung fehlgeschlagen: %v", err)
	}

	resp, err := c.client.Post(c.baseURL+"/employees", "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("HTTP-Request fehlgeschlagen: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (c *APIClient) GetEmployee(id string) (Employee, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/employees/"+id, nil)
	if err != nil {
		return Employee{}, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", c.token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return Employee{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Employee{}, fmt.Errorf("API error %d", resp.StatusCode)
	}

	var employee Employee
	if err := json.NewDecoder(resp.Body).Decode(&employee); err != nil {
		return Employee{}, err
	}
	return employee, nil
}

func (c *APIClient) UpdateEmployee(id string, employee Employee) error {
	jsonData, err := json.Marshal(employee)
	if err != nil {
		return fmt.Errorf("JSON-Serialisierung fehlgeschlagen: %v", err)
	}

	req, err := http.NewRequest("PUT", c.baseURL+"/employees/"+id, strings.NewReader(string(jsonData)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP-Request fehlgeschlagen: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (c *APIClient) DeleteEmployee(id string) error {
	req, err := http.NewRequest("DELETE", c.baseURL+"/employees/"+id, nil)
	if err != nil {
		return err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP-Request fehlgeschlagen: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (c *APIClient) UpdateAsset(id string, asset Asset) error {
	jsonData, err := json.Marshal(asset)
	if err != nil {
		return fmt.Errorf("JSON-Serialisierung fehlgeschlagen: %v", err)
	}

	log.Printf("🔄 UpdateAsset API call: PUT %s/assets/%s", c.baseURL, id)
	log.Printf("📊 Asset data: %s", string(jsonData))

	req, err := http.NewRequest("PUT", c.baseURL+"/assets/"+id, strings.NewReader(string(jsonData)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// *** KRITISCH: TOKEN HINZUFÜGEN ***
	if c.token != "" {
		req.Header.Set("Authorization", c.token)
		log.Printf("🔑 Authorization header set: %s", c.token[:20]+"...")
	} else {
		log.Printf("⚠️ No token available for UpdateAsset")
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP-Request fehlgeschlagen: %v", err)
	}
	defer resp.Body.Close()

	log.Printf("📡 API response status: %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("❌ API error response: %s", string(body))
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("✅ UpdateAsset successful")
	return nil
}

func (c *APIClient) DeleteAsset(id string) error {
	req, err := http.NewRequest("DELETE", c.baseURL+"/assets/"+id, nil)
	if err != nil {
		return err
	}

	// TOKEN HINZUFÜGEN
	if c.token != "" {
		req.Header.Set("Authorization", c.token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP-Request fehlgeschlagen: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (c *APIClient) AssignAsset(assetID string, employeeID uint, notes string) error {
	assignmentData := map[string]interface{}{
		"employee_id": employeeID,
		"notes":       notes,
	}

	jsonData, err := json.Marshal(assignmentData)
	if err != nil {
		return fmt.Errorf("JSON-Serialisierung fehlgeschlagen: %v", err)
	}

	log.Printf("🔄 AssignAsset API call: POST %s/assets/%s/assign", c.baseURL, assetID)
	log.Printf("📊 Assignment data: %s", string(jsonData))

	req, err := http.NewRequest("POST", c.baseURL+"/assets/"+assetID+"/assign", strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("Failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// *** KRITISCH: TOKEN HINZUFÜGEN ***
	if c.token != "" {
		req.Header.Set("Authorization", c.token)
		log.Printf("🔑 Authorization header set for assign: %s", c.token[:20]+"...")
	} else {
		log.Printf("⚠️ No token available for AssignAsset")
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP-Request fehlgeschlagen: %v", err)
	}
	defer resp.Body.Close()

	log.Printf("📡 AssignAsset API response status: %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("❌ AssignAsset API error response: %s", string(body))
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("✅ AssignAsset successful")
	return nil
}

// UnassignAsset - Asset zurückgeben/unassign mit Token-Support
func (c *APIClient) UnassignAsset(assetID string, notes string) error {
	unassignData := map[string]interface{}{
		"notes": notes,
		"force": true,
	}

	jsonData, err := json.Marshal(unassignData)
	if err != nil {
		return fmt.Errorf("JSON-Serialisierung fehlgeschlagen: %v", err)
	}

	log.Printf("🔄 UnassignAsset API call: POST %s/assets/%s/unassign", c.baseURL, assetID)
	log.Printf("📊 Unassign data: %s", string(jsonData))

	req, err := http.NewRequest("POST", c.baseURL+"/assets/"+assetID+"/unassign", strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("Failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// *** KRITISCH: TOKEN HINZUFÜGEN ***
	if c.token != "" {
		req.Header.Set("Authorization", c.token)
		log.Printf("🔑 Authorization header set for unassign: %s", c.token[:20]+"...")
	} else {
		log.Printf("⚠️ No token available for UnassignAsset")
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP-Request fehlgeschlagen: %v", err)
	}
	defer resp.Body.Close()

	log.Printf("📡 UnassignAsset API response status: %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("❌ UnassignAsset API error response: %s", string(body))
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("✅ UnassignAsset successful")
	return nil
}

// TransferAsset - Asset an anderen Mitarbeiter übertragen mit Token-Support
func (c *APIClient) TransferAsset(assetID string, toEmployeeID uint, notes string) error {
	transferData := map[string]interface{}{
		"to_employee_id": toEmployeeID,
		"notes":          notes,
	}

	jsonData, err := json.Marshal(transferData)
	if err != nil {
		return fmt.Errorf("JSON-Serialisierung fehlgeschlagen: %v", err)
	}

	log.Printf("🔄 TransferAsset API call: POST %s/assets/%s/transfer", c.baseURL, assetID)
	log.Printf("📊 Transfer data: %s", string(jsonData))

	req, err := http.NewRequest("POST", c.baseURL+"/assets/"+assetID+"/transfer", strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("Failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// *** KRITISCH: TOKEN HINZUFÜGEN ***
	if c.token != "" {
		req.Header.Set("Authorization", c.token)
		log.Printf("🔑 Authorization header set for transfer: %s", c.token[:20]+"...")
	} else {
		log.Printf("⚠️ No token available for TransferAsset")
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP-Request fehlgeschlagen: %v", err)
	}
	defer resp.Body.Close()

	log.Printf("📡 TransferAsset API response status: %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("❌ TransferAsset API error response: %s", string(body))
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("✅ TransferAsset successful")
	return nil
}

// CheckSerialNumberHandler - Prüft ob Seriennummer bereits existiert
func (fs *FrontendServer) CheckSerialNumberHandler(c *gin.Context) {
	serialNumber := c.Query("serial")
	if serialNumber == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Seriennummer erforderlich"})
		return
	}

	apiClient := NewAPIClient(fs.apiURL)
	assets, err := apiClient.GetAssets()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Fehler beim Abrufen der Assets"})
		return
	}

	// Check if serial number exists
	exists := false
	for _, asset := range assets {
		if asset.SerialNumber == serialNumber {
			exists = true
			break
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"exists":        exists,
		"serial_number": serialNumber,
		"available":     !exists,
	})
}

// GenerateSerialNumberHandler - Generiert eine eindeutige Seriennummer
func (fs *FrontendServer) GenerateSerialNumberHandler(c *gin.Context) {
	deviceType := c.Query("type")
	if deviceType == "" {
		deviceType = "ASSET"
	}

	// Generate prefix from device type
	prefix := strings.ToUpper(deviceType)
	if len(prefix) > 2 {
		prefix = prefix[:2]
	}

	// Generate random part
	charset := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	randomPart := make([]byte, 8)
	for i := range randomPart {
		randomPart[i] = charset[rand.Intn(len(charset))]
	}

	serialNumber := prefix + string(randomPart)

	// Ensure uniqueness by checking against existing assets
	apiClient := NewAPIClient(fs.apiURL)
	assets, err := apiClient.GetAssets()
	if err == nil {
		// If serial exists, try again with different random part
		maxAttempts := 10
		attempts := 0

		for attempts < maxAttempts {
			exists := false
			for _, asset := range assets {
				if asset.SerialNumber == serialNumber {
					exists = true
					break
				}
			}

			if !exists {
				break
			}

			// Generate new random part
			for i := range randomPart {
				randomPart[i] = charset[rand.Intn(len(charset))]
			}
			serialNumber = prefix + string(randomPart)
			attempts++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"serial_number": serialNumber,
		"device_type":   deviceType,
		"generated_at":  time.Now(),
	})
}

// DebugAssetsHandler - Debug-Handler für Asset-Probleme
func (fs *FrontendServer) DebugAssetsHandler(c *gin.Context) {
	apiClient := NewAPIClient(fs.apiURL)

	log.Printf("🔍 Debug: Fetching assets from API...")

	// Test direct API call
	resp, err := apiClient.client.Get(apiClient.baseURL + "/assets")
	if err != nil {
		log.Printf("❌ Debug: Direct API call failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "API call failed", "details": err.Error()})
		return
	}
	defer resp.Body.Close()

	// Read raw response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("❌ Debug: Failed to read response body: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read response"})
		return
	}

	log.Printf("📡 Debug: Raw API response status: %d", resp.StatusCode)
	log.Printf("📡 Debug: Raw API response body: %s", string(body))

	// Parse JSON
	var assets []Asset
	if err := json.Unmarshal(body, &assets); err != nil {
		log.Printf("❌ Debug: JSON parsing failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":       "JSON parsing failed",
			"raw_body":    string(body),
			"parse_error": err.Error(),
		})
		return
	}

	log.Printf("✅ Debug: Successfully parsed %d assets", len(assets))
	for i, asset := range assets {
		log.Printf("   Asset %d: ID=%d, Type=%s, Serial=%s, Status=%s",
			i+1, asset.ID, asset.DeviceType, asset.SerialNumber, asset.Status)
	}

	// Test employees as well
	employees, err := apiClient.GetEmployees()
	if err != nil {
		log.Printf("⚠️ Debug: Failed to fetch employees: %v", err)
	} else {
		log.Printf("✅ Debug: Successfully fetched %d employees", len(employees))
	}

	c.JSON(http.StatusOK, gin.H{
		"debug":           "Asset fetch analysis",
		"api_url":         apiClient.baseURL,
		"assets_count":    len(assets),
		"assets":          assets,
		"employees_count": len(employees),
		"response_status": resp.StatusCode,
	})
}

// AssetsHandlerDebug - Debug-Version des Assets-Handlers
func (fs *FrontendServer) AssetsHandlerDebug(c *gin.Context) {
	apiClient := NewAPIClient(fs.apiURL)

	log.Printf("🎯 AssetsHandler: Starting...")
	log.Printf("📍 API URL: %s", fs.apiURL)

	assets, err := apiClient.GetAssets()
	if err != nil {
		log.Printf("❌ AssetsHandler: Error fetching assets: %v", err)
		c.String(http.StatusInternalServerError, "Error fetching assets: %v", err)
		return
	}

	log.Printf("📦 AssetsHandler: Fetched %d assets", len(assets))
	for i, asset := range assets {
		log.Printf("   Asset %d: %+v", i+1, asset)
	}

	employees, err := apiClient.GetEmployees()
	if err != nil {
		log.Printf("⚠️ AssetsHandler: Error fetching employees: %v", err)
		employees = []Employee{}
	}

	log.Printf("👥 AssetsHandler: Fetched %d employees", len(employees))

	data := PageData{
		Title:      "Assets (Debug Mode)",
		APIBaseURL: fs.apiURL,
		Assets:     assets,
		Employees:  employees,
	}

	log.Printf("📄 AssetsHandler: Rendering template with %d assets, %d employees", len(data.Assets), len(data.Employees))

	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := fs.templates.ExecuteTemplate(c.Writer, "assets.html", data); err != nil {
		log.Printf("❌ AssetsHandler: Template error: %v", err)
		c.String(http.StatusInternalServerError, "Template error: %v", err)
	} else {
		log.Printf("✅ AssetsHandler: Template rendered successfully")
	}
}

// FlushCacheHandler - Cache-Flush für Debug
func (fs *FrontendServer) FlushCacheHandler(c *gin.Context) {
	// Versuche Cache über Backend zu leeren
	apiClient := NewAPIClient(fs.apiURL)

	// Test verschiedene Cache-Flush Endpunkte
	endpoints := []string{
		"/admin/cache/flush",
		"/admin/cache/clear",
		"/api/cache/flush",
		"/flush-cache",
	}

	results := make(map[string]interface{})

	for _, endpoint := range endpoints {
		resp, err := apiClient.client.Post(apiClient.baseURL+endpoint, "application/json", nil)
		if err != nil {
			results[endpoint] = map[string]interface{}{"error": err.Error()}
			continue
		}
		resp.Body.Close()
		results[endpoint] = map[string]interface{}{"status": resp.StatusCode}
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "Cache flush attempted",
		"results":   results,
		"timestamp": time.Now(),
	})
}
func (fs *FrontendServer) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Printf("🔍 Clean auth middleware for: %s %s", c.Request.Method, c.Request.URL.Path)

		// Diese Middleware wird NUR auf geschützte Routen angewendet
		// Keine Pfad-Prüfung nötig!

		token := fs.extractToken(c)

		if token == "" {
			log.Printf("❌ No token found for protected route: %s", c.Request.URL.Path)

			if strings.HasPrefix(c.Request.URL.Path, "/api/") {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
			} else {
				c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Bitte melden Sie sich an"))
			}
			c.Abort()
			return
		}

		// Token validieren
		if !fs.validateToken(c, token) {
			log.Printf("❌ Token validation failed for: %s", c.Request.URL.Path)
			c.SetCookie("auth_token", "", -1, "/", "", false, true)
			c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Sitzung abgelaufen"))
			c.Abort()
			return
		}

		log.Printf("✅ Authentication successful for: %s %s", c.Request.Method, c.Request.URL.Path)
		c.Next()
	}
}

func (fs *FrontendServer) validateToken(c *gin.Context, token string) bool {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", fs.apiURL+"/user/profile", nil)
	if err != nil {
		log.Printf("❌ Failed to create validation request: %v", err)
		return false
	}

	req.Header.Set("Authorization", token)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("❌ Backend validation request failed: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("❌ Token validation failed: %d", resp.StatusCode)
		return false
	}

	var employee Employee
	if err := json.NewDecoder(resp.Body).Decode(&employee); err != nil {
		log.Printf("❌ Failed to decode user data: %v", err)
		return false
	}

	log.Printf("✅ Token valid for user: %s %s", employee.FirstName, employee.LastName)
	c.Set("employee", employee)
	c.Set("auth_token", token)
	return true
}

// Erweiterte setupFrontendRoutes mit Authentication
func setupFrontendRoutes(apiURL string) *gin.Engine {
	r := gin.Default()

	// Global Middlewares
	r.Use(corsMiddleware())
	r.Static("/static", "./static")

	fs := NewFrontendServer(apiURL)

	// Debug-Middleware
	r.Use(func(c *gin.Context) {
		log.Printf("🌐 REQUEST: %s %s", c.Request.Method, c.Request.URL.Path)
		c.Next()
		log.Printf("📤 RESPONSE: %s %s -> %d", c.Request.Method, c.Request.URL.Path, c.Writer.Status())
	})

	// ===== PUBLIC ROUTES (KEINE AUTH-MIDDLEWARE) =====
	r.GET("/login", fs.LoginHandler)
	r.POST("/login", fs.LoginPostHandler)
	// r.GET("/logout", fs.LogoutHandler)
	r.GET("/logout", fs.LogoutHandlerWithIntermediate)
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":   "healthy",
			"frontend": "running",
			"api_url":  apiURL,
			"time":     time.Now(),
		})
	})

	// Debug routes (nur in development)
	r.GET("/debug/routes", fs.DebugRoutesHandler)
	r.GET("/debug/auth", fs.DebugAuthHandler)
	r.GET("/debug/token", fs.DebugTokenHandler)

	// ===== PROTECTED ROUTES GROUP =====
	protected := r.Group("/")
	protected.Use(fs.authMiddleware()) // ← Hier direkt aufrufen
	{
		protected.GET("/", fs.IndexHandler)
		protected.GET("/assets", fs.AssetsHandler)
		protected.GET("/assets/:id/history", fs.AssetHistoryHandler)
		protected.GET("/employees", fs.EmployeesHandler)

		// Weitere geschützte Routen...
	}

	// ===== ADMIN ROUTES GROUP =====
	admin := r.Group("/")
	admin.Use(fs.authMiddleware())  // ← Auth erst
	admin.Use(fs.adminMiddleware()) // ← Dann Admin-Check
	{
		// Asset Management
		admin.GET("/assets/create", fs.CreateAssetHandler)
		admin.POST("/assets/create", fs.CreateAssetPostHandler)
		admin.GET("/assets/:id/edit", fs.EditAssetHandler)
		admin.POST("/assets/:id/edit", fs.EditAssetPostHandler)
		admin.POST("/assets/:id/delete", fs.DeleteAssetHandler)
		admin.GET("/assets/:id/manage", fs.AssetManagementHandler)

		// Employee Management
		admin.GET("/employees/create", fs.CreateEmployeeHandler)
		admin.POST("/employees/create", fs.CreateEmployeePostHandler)
		admin.GET("/employees/:id/edit", fs.EditEmployeeHandler)
		admin.POST("/employees/:id/edit", fs.EditEmployeePostHandler)
		admin.POST("/employees/:id/delete", fs.DeleteEmployeeHandler)

		// Password Management
		admin.GET("/employees/:id/password", fs.SetPasswordHandler)
		admin.POST("/employees/:id/password", fs.SetPasswordPostHandler)

		// Admin Dashboard
		admin.GET("/admin", fs.AdminDashboardHandler)
		admin.GET("/admin/users", fs.UserManagementHandler)
	}

	// ===== API PROXY =====
	api := r.Group("/api")
	{
		api.Any("/*path", fs.APIProxyHandler)
	}

	return r
}

func (fs *FrontendServer) LoginPostHandler(c *gin.Context) {
	log.Printf("📨 Login POST request from: %s", c.ClientIP())

	email := c.PostForm("email")
	password := c.PostForm("password")

	log.Printf("🔐 Login attempt for email: %s", email)

	if email == "" || password == "" {
		log.Printf("❌ Login failed: missing credentials")
		c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("E-Mail und Passwort erforderlich"))
		return
	}

	// Login-Daten an Backend senden
	loginData := map[string]string{
		"email":    email,
		"password": password,
	}

	jsonData, err := json.Marshal(loginData)
	if err != nil {
		log.Printf("❌ JSON marshal error: %v", err)
		c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Interner Fehler"))
		return
	}

	log.Printf("📤 Sending login request to backend: %s/auth/login", fs.apiURL)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(fs.apiURL+"/auth/login", "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		log.Printf("❌ Login request failed: %v", err)
		c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Verbindungsfehler zum Server"))
		return
	}
	defer resp.Body.Close()

	log.Printf("📨 Login response status: %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("❌ Login failed: %d - %s", resp.StatusCode, string(body))

		var errorMsg string
		switch resp.StatusCode {
		case 401:
			errorMsg = "Ungültige E-Mail oder Passwort"
		case 403:
			errorMsg = "Account ist deaktiviert"
		case 429:
			errorMsg = "Zu viele Login-Versuche. Bitte versuchen Sie es später erneut"
		default:
			errorMsg = "Login fehlgeschlagen. Bitte versuchen Sie es erneut"
		}

		c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape(errorMsg))
		return
	}

	var loginResponse LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResponse); err != nil {
		log.Printf("❌ Login response decode error: %v", err)
		c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Serverantwort konnte nicht verarbeitet werden"))
		return
	}

	log.Printf("✅ Login successful for user: %s", email)
	log.Printf("🍪 Setting auth cookie with token")

	// Token als Cookie setzen
	// Berechne Ablaufzeit (z.B. 24 Stunden oder aus loginResponse.ExpiresAt)
	maxAge := int(time.Until(loginResponse.ExpiresAt).Seconds())
	if maxAge <= 0 {
		maxAge = 24 * 60 * 60 // 24 Stunden als Fallback
	}

	c.SetCookie("auth_token", loginResponse.Token, maxAge, "/", "", false, true)

	// Erfolgreiche Weiterleitung
	redirectTo := c.Query("redirect")
	if redirectTo == "" {
		redirectTo = "/"
	}

	log.Printf("🎯 Redirecting to: %s", redirectTo)
	c.Redirect(http.StatusSeeOther, redirectTo)
}

// DebugAuthHandler - Debug-Informationen für Authentifizierung
func (fs *FrontendServer) DebugAuthHandler(c *gin.Context) {
	log.Printf("🔍 Debug auth handler called for: %s", c.Request.URL.Path)

	authHeader := c.GetHeader("Authorization")
	cookie, cookieErr := c.Cookie("auth_token")
	queryToken := c.Query("token")

	// Alle Cookies sammeln
	var allCookies []gin.H
	for _, cookie := range c.Request.Cookies() {
		allCookies = append(allCookies, gin.H{
			"name":  cookie.Name,
			"value": cookie.Value,
		})
	}

	// Token-Validierung testen (falls vorhanden)
	var tokenValidation gin.H
	token := ""

	if authHeader != "" {
		token = authHeader
	} else if cookie != "" {
		token = "Bearer " + cookie
	}

	if token != "" {
		log.Printf("🧪 Testing token validation...")
		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequest("GET", fs.apiURL+"/user/profile", nil)
		if err == nil {
			req.Header.Set("Authorization", token)
			resp, err := client.Do(req)
			if err == nil {
				defer resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					var employee Employee
					if json.NewDecoder(resp.Body).Decode(&employee) == nil {
						tokenValidation = gin.H{
							"valid": true,
							"user":  fmt.Sprintf("%s %s (%s)", employee.FirstName, employee.LastName, employee.Email),
							"admin": employee.IsAdmin,
						}
					} else {
						tokenValidation = gin.H{"valid": true, "decode_error": true}
					}
				} else {
					tokenValidation = gin.H{
						"valid":       false,
						"status_code": resp.StatusCode,
					}
				}
			} else {
				tokenValidation = gin.H{
					"valid": false,
					"error": err.Error(),
				}
			}
		} else {
			tokenValidation = gin.H{
				"valid":         false,
				"request_error": err.Error(),
			}
		}
	} else {
		tokenValidation = gin.H{"no_token": true}
	}

	c.JSON(http.StatusOK, gin.H{
		"debug_info": gin.H{
			"timestamp": time.Now(),
			"request": gin.H{
				"path":       c.Request.URL.Path,
				"method":     c.Request.Method,
				"query":      c.Request.URL.RawQuery,
				"user_agent": c.GetHeader("User-Agent"),
				"ip":         c.ClientIP(),
				"referer":    c.GetHeader("Referer"),
			},
			"auth": gin.H{
				"auth_header":  authHeader,
				"cookie_value": cookie,
				"cookie_error": cookieErr,
				"query_token":  queryToken,
				"all_cookies":  allCookies,
				"token_used":   token,
			},
			"validation": tokenValidation,
			"backend": gin.H{
				"api_url": fs.apiURL,
			},
		},
	})
}

// UserManagementHandler - Benutzerverwaltung für Admins
func (fs *FrontendServer) UserManagementHandler(c *gin.Context) {
	apiClient := NewAPIClient(fs.apiURL)

	// Get auth token
	token := c.GetHeader("Authorization")
	if token == "" {
		if cookie, err := c.Cookie("auth_token"); err == nil {
			token = "Bearer " + cookie
		}
	}

	// Get all employees
	employees, err := apiClient.GetEmployeesWithAuth(token)
	if err != nil {
		log.Printf("Error fetching employees: %v", err)
		employees = []Employee{}
	}

	// Get current user from context
	currentEmployee, exists := c.Get("employee")
	if !exists {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}

	emp := currentEmployee.(Employee)

	data := struct {
		Title       string
		Employees   []Employee
		CurrentUser Employee
		APIBaseURL  string
		Version     string
	}{
		Title:       "Benutzerverwaltung",
		Employees:   employees,
		CurrentUser: emp,
		APIBaseURL:  fs.apiURL,
		Version:     Version,
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := fs.templates.ExecuteTemplate(c.Writer, "user_management.html", data); err != nil {
		log.Printf("Template error: %v", err)
		c.String(http.StatusInternalServerError, "Template error: %v", err)
	}
}

// AdminDashboardHandler erweitern
func (fs *FrontendServer) AdminDashboardHandler(c *gin.Context) {
	apiClient := NewAPIClient(fs.apiURL)

	// Get auth token
	token := c.GetHeader("Authorization")
	if token == "" {
		if cookie, err := c.Cookie("auth_token"); err == nil {
			token = "Bearer " + cookie
		}
	}

	// Get current user from context
	employee, exists := c.Get("employee")
	if !exists {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}

	emp := employee.(Employee)

	// Get statistics
	assets, err := apiClient.GetAssetsWithAuth(token)
	if err != nil {
		log.Printf("Error fetching assets: %v", err)
		assets = []Asset{}
	}

	employees, err := apiClient.GetEmployeesWithAuth(token)
	if err != nil {
		log.Printf("Error fetching employees: %v", err)
		employees = []Employee{}
	}

	// Calculate statistics
	totalAssets := len(assets)
	assignedAssets := 0
	availableAssets := 0
	maintenanceAssets := 0

	for _, asset := range assets {
		switch asset.Status {
		case "assigned":
			assignedAssets++
		case "available":
			availableAssets++
		case "maintenance":
			maintenanceAssets++
		}
	}

	totalEmployees := len(employees)
	adminEmployees := 0
	activeEmployees := 0

	for _, employee := range employees {
		if employee.IsAdmin {
			adminEmployees++
		}
		if employee.IsActive {
			activeEmployees++
		}
	}

	data := struct {
		Title             string
		CurrentUser       Employee
		APIBaseURL        string
		Assets            []Asset
		Employees         []Employee
		Template          string // Fehlendes Feld hinzufügen
		TotalAssets       int
		AssignedAssets    int
		AvailableAssets   int
		MaintenanceAssets int
		TotalEmployees    int
		AdminEmployees    int
		ActiveEmployees   int
		RecentAssets      []Asset
		RecentEmployees   []Employee
		Version           string // Version hinzufügen
		Stage             string // Stage hinzufügen
	}{
		Title:             "Administration Dashboard",
		CurrentUser:       emp,
		APIBaseURL:        fs.apiURL,
		Assets:            assets,
		Employees:         employees,
		Template:          "admin-dashboard-content", // Template setzen
		TotalAssets:       totalAssets,
		AssignedAssets:    assignedAssets,
		AvailableAssets:   availableAssets,
		MaintenanceAssets: maintenanceAssets,
		TotalEmployees:    totalEmployees,
		AdminEmployees:    adminEmployees,
		ActiveEmployees:   activeEmployees,
		RecentAssets:      getRecentAssets(assets, 5),
		RecentEmployees:   getRecentEmployees(employees, 5),
		Version:           Version, // Version hinzufügen
		Stage:             Stage,   // Stage hinzufügen
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := fs.templates.ExecuteTemplate(c.Writer, "admin_dashboard.html", data); err != nil {
		log.Printf("Template error: %v", err)
		c.String(http.StatusInternalServerError, "Template error: %v", err)
	}
}

// Helper functions
func getRecentAssets(assets []Asset, limit int) []Asset {
	if len(assets) <= limit {
		return assets
	}

	// Sort by CreatedAt (newest first) - simplified version
	recent := make([]Asset, 0, limit)
	for i := 0; i < limit && i < len(assets); i++ {
		recent = append(recent, assets[i])
	}
	return recent
}

func getRecentEmployees(employees []Employee, limit int) []Employee {
	if len(employees) <= limit {
		return employees
	}

	// Sort by CreatedAt (newest first) - simplified version
	recent := make([]Employee, 0, limit)
	for i := 0; i < limit && i < len(employees); i++ {
		recent = append(recent, employees[i])
	}
	return recent
}

// API Client methods with authentication
func (c *APIClient) GetEmployeesWithAuth(token string) ([]Employee, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/employees", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error %d", resp.StatusCode)
	}

	var employees []Employee
	if err := json.NewDecoder(resp.Body).Decode(&employees); err != nil {
		return nil, err
	}
	return employees, nil
}

func (c *APIClient) GetAssetsWithAuth(token string) ([]Asset, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/assets", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error %d", resp.StatusCode)
	}

	var assets []Asset
	if err := json.NewDecoder(resp.Body).Decode(&assets); err != nil {
		return nil, err
	}
	return assets, nil
}

func (fs *FrontendServer) SetPasswordHandler(c *gin.Context) {
	employeeID := c.Param("id")
	apiClient := NewAPIClient(fs.apiURL)

	// TOKEN EXTRAHIEREN UND SETZEN
	token := fs.extractToken(c)
	if token != "" {
		apiClient.SetToken(token)
		log.Printf("🔑 Token set for SetPasswordHandler")
	} else {
		log.Printf("❌ No token found in SetPasswordHandler")
		c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Authentifizierung erforderlich"))
		return
	}

	// Get current user from context
	employeea, exists := c.Get("employee")
	if !exists {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}

	emp := employeea.(Employee)

	employee, err := apiClient.GetEmployee(employeeID)
	if err != nil {
		log.Printf("❌ Error fetching employee: %v", err)
		if strings.Contains(err.Error(), "401") {
			c.Redirect(http.StatusSeeOther, "/login?error="+url.QueryEscape("Sitzung abgelaufen"))
			return
		}
		c.String(http.StatusNotFound, "Employee not found: %v", err)
		return
	}

	data := PageData{
		Title:       fmt.Sprintf("Mitarbeiter bearbeiten - %s %s", employee.FirstName, employee.LastName),
		Employee:    &employee,    // Einzelner Employee (erweitere PageData um dieses Feld)
		Employees:   []Employee{}, // Leeres Array für Template-Kompatibilität
		Assets:      []Asset{},    // Leeres Array für Template-Kompatibilität
		APIBaseURL:  fs.apiURL,
		Template:    "set-password-content",
		CurrentUser: emp,
	}

	// data := struct {
	// 	Title       string
	// 	Employee    Employee
	// 	APIBaseURL  string
	// 	CurrentUser Employee
	// 	Template    string
	// }{
	// 	Title:       fmt.Sprintf("Passwort setzen - %s %s", employee.FirstName, employee.LastName),
	// 	Employee:    employee,
	// 	APIBaseURL:  fs.apiURL,
	// 	CurrentUser: emp,
	// 	Template:    "set_password",
	// }

	// c.HTML(http.StatusOK, "set_password.html", data)
	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := fs.templates.ExecuteTemplate(c.Writer, "set_password.html", data); err != nil {
		log.Printf("❌ Template execution error: %v", err)
		c.String(http.StatusInternalServerError, "Template rendering error: %v", err)
		return
	}
}

func (fs *FrontendServer) SetPasswordPostHandler(c *gin.Context) {
	employeeID := c.Param("id")
	password := c.PostForm("password")
	confirmPassword := c.PostForm("confirm_password")

	if password == "" || len(password) < 6 {
		c.Redirect(http.StatusSeeOther, fmt.Sprintf("/employees/%s/password?error=%s", employeeID, url.QueryEscape("Passwort muss mindestens 6 Zeichen lang sein")))
		return
	}

	if password != confirmPassword {
		c.Redirect(http.StatusSeeOther, fmt.Sprintf("/employees/%s/password?error=%s", employeeID, url.QueryEscape("Passwörter stimmen nicht überein")))
		return
	}

	// Get auth token
	token := c.GetHeader("Authorization")
	if token == "" {
		if cookie, err := c.Cookie("auth_token"); err == nil {
			token = "Bearer " + cookie
		}
	}

	// Call backend API to set password
	client := &http.Client{Timeout: 10 * time.Second}

	passwordData := map[string]string{"password": password}
	jsonData, _ := json.Marshal(passwordData)

	req, err := http.NewRequest("POST", fs.apiURL+"/employees/"+employeeID+"/set-password", strings.NewReader(string(jsonData)))
	if err != nil {
		c.Redirect(http.StatusSeeOther, fmt.Sprintf("/employees/%s/password?error=%s", employeeID, url.QueryEscape("Fehler beim Setzen des Passworts")))
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", token)

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		c.Redirect(http.StatusSeeOther, fmt.Sprintf("/employees/%s/password?error=%s", employeeID, url.QueryEscape("Fehler beim Setzen des Passworts")))
		return
	}
	resp.Body.Close()

	c.Redirect(http.StatusSeeOther, "/employees?success="+url.QueryEscape("Passwort wurde erfolgreich gesetzt"))
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func loadConfig() Config {
	return Config{
		APIUrl:      getEnv("API_URL", "http://localhost:8090"),
		Port:        getEnv("PORT", "3000"),
		Environment: getEnv("ENVIRONMENT", "development"),
		Debug:       getEnv("DEBUG", "false") == "true",
	}
}

var (
	Version = "dev" // Default-Wert
	Stage   = "dev" // Default-Wert
)

// Main Frontend Server
func main() {
	// Initialize random seed for serial number generation
	rand.Seed(time.Now().UnixNano())

	config := loadConfig()

	// Configuration
	// apiURL := "http://localhost:8090" // Backend API URL
	// apiURL := "https://assets-api.dev.kuepper.nrw"
	apiURL := getEnv("API_URL", "http://localhost:8090")
	// frontendPort := ":3000" // Frontend Port
	frontendPort := ":" + config.Port
	// Check command line arguments
	if len(os.Args) > 1 {
		frontendPort = ":" + os.Args[1]
	}
	if len(os.Args) > 2 {
		apiURL = "http://localhost:" + os.Args[2]
	}

	// Setup Routes
	r := setupFrontendRoutes(apiURL)
	if envVersion := os.Getenv("VERSION"); envVersion != "" {
		Version = envVersion
	}
	if envStage := os.Getenv("APP_STAGE"); envStage != "" {
		Stage = envStage
	}

	log.Printf("Starting Asset Manager %s (%s)", Version, Stage)
	log.Printf("🎨 Frontend Server starting...")
	log.Printf("📍 Frontend Port: %s", config.Port)
	log.Printf("🔗 Backend API URL: %s", config.APIUrl)
	log.Println("🌐 Frontend URLs:")
	log.Printf("   Dashboard: http://localhost%s/", frontendPort)
	log.Printf("   Assets:    http://localhost%s/assets", frontendPort)
	log.Printf("   Employees: http://localhost%s/employees", frontendPort)
	log.Printf("   Health:    http://localhost%s/health", frontendPort)
	log.Printf("   Debug:     http://localhost%s/debug/assets", frontendPort)
	log.Println("🚀 Frontend Server ready!")

	// Start server
	if err := r.Run(frontendPort); err != nil {
		log.Fatal("❌ Failed to start frontend server:", err)
	}
}
