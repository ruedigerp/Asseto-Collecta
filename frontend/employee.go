package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

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

	isAdmin := c.PostForm("is_admin") == "on" // ✅ Das funktioniert

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

	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := fs.templates.ExecuteTemplate(c.Writer, "edit_employee.html", data); err != nil {
		log.Printf("Template error: %v", err)
		c.String(http.StatusInternalServerError, "Template error: %v", err)
	}
}

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
