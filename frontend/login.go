package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Login page handler
func (fs *FrontendServer) LoginHandler(c *gin.Context) {
	data := PageData{
		Title:      "Login",
		APIBaseURL: fs.apiURL,
		Version:    Version,
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := fs.templates.ExecuteTemplate(c.Writer, "login.html", data); err != nil {
		log.Printf("Template error: %v", err)
		c.String(http.StatusInternalServerError, "Template error: %v", err)
	}
}

// Frontend Authentication Handlers - Fügen Sie diese zu Ihrer Frontend main.go hinzu

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

func (c *APIClient) SetToken(token string) {
	c.token = token
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

func (fs *FrontendServer) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Printf("🔍 Clean auth middleware for: %s %s", c.Request.Method, c.Request.URL.Path)

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
