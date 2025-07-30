package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

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

	data := PageData{
		Title:       fmt.Sprintf("Asset bearbeiten - %s", asset.DeviceType),
		Asset:       &asset, // Pointer verwenden
		Assets:      []Asset{asset},
		Employees:   employees,
		APIBaseURL:  fs.apiURL,
		CurrentUser: emp,
		Template:    "asset-edit-content",
		Version:     Version,
		Stage:       Stage,
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

	data := PageData{
		Title:       fmt.Sprintf("Asset History - %s", asset.DeviceType),
		Asset:       &asset,
		Assets:      []Asset{asset},
		History:     history,
		Employees:   employees,
		APIBaseURL:  fs.apiURL,
		Template:    "assets-history-content",
		CurrentUser: emp,
		Version:     Version,
		Stage:       Stage,
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

	data := PageData{
		Title:       fmt.Sprintf("Asset verwalten - %s", asset.DeviceType),
		Asset:       &asset,
		Assets:      []Asset{asset},
		Employees:   employees,
		APIBaseURL:  fs.apiURL,
		CurrentUser: emp,
		Template:    "asset-manage-content",
		Version:     Version,
		Stage:       Stage,
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
