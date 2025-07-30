package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

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

	data := PageData{
		Title:       "Benutzerverwaltung",
		Employees:   employees,
		CurrentUser: emp,
		APIBaseURL:  fs.apiURL,
		Template:    "user-management-content",
		Version:     Version,
		Stage:       Stage,
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

	data := PageData{
		Title:             "Administration Dashboard",
		CurrentUser:       emp,
		APIBaseURL:        fs.apiURL,
		Assets:            assets,
		Employees:         employees,
		Template:          "admin-dashboard-content",
		TotalAssets:       totalAssets,
		AssignedAssets:    assignedAssets,
		AvailableAssets:   availableAssets,
		MaintenanceAssets: maintenanceAssets,
		TotalEmployees:    totalEmployees,
		AdminEmployees:    adminEmployees,
		ActiveEmployees:   activeEmployees,
		RecentAssets:      getRecentAssets(assets, 5),
		RecentEmployees:   getRecentEmployees(employees, 5),
		Version:           Version,
		Stage:             Stage,
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := fs.templates.ExecuteTemplate(c.Writer, "admin_dashboard.html", data); err != nil {
		log.Printf("Template error: %v", err)
		c.String(http.StatusInternalServerError, "Template error: %v", err)
	}
}
