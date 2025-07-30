package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"reflect"
	"time"

	"github.com/gin-gonic/gin"
)

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
