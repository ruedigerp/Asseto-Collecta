package main

import (
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

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
		// admin.GET("/admin/users", fs.UserManagementHandler)
	}

	// ===== API PROXY =====
	api := r.Group("/api")
	{
		api.Any("/*path", fs.APIProxyHandler)
	}

	return r
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
