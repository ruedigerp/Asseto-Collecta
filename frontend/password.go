package main

// func main() {
// 	password := "admin123"

// 	// Generate hash
// 	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	fmt.Printf("Passwort: %s\n", password)
// 	fmt.Printf("Hash: %s\n", string(hash))

// 	// Verify hash
// 	err = bcrypt.CompareHashAndPassword(hash, []byte(password))
// 	if err != nil {
// 		fmt.Println("❌ Hash verification failed")
// 	} else {
// 		fmt.Println("✅ Hash verification successful")
// 	}

// 	// SQL Update Statement
// 	fmt.Printf("\nSQL Update:\n")
// 	fmt.Printf("UPDATE employees SET password_hash = '%s' WHERE email = 'ruediger@mogenius.com';\n", string(hash))
// }
