package user

import (
	"email-platform/config"
	"email-platform/utils"
	"encoding/csv"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"golang.org/x/exp/rand"
)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func LoginHandler(c echo.Context) error {
	req := new(LoginRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	var user User
	err := config.DB.Get(&user, "SELECT * FROM users WHERE email = ?", req.Email)
	if err != nil || !utils.CheckPasswordHash(req.Password, user.Password) {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
	}

	token, err := utils.GenerateJWT(user.ID, user.Email)
	if err != nil {
		fmt.Println("GenerateJWT", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Update last login
	err = updateLastLogin(user.ID)
	if err != nil {
		fmt.Println("error updateLastLogin", err)
	}

	return c.JSON(http.StatusOK, map[string]string{"token": token})
}

func LogoutHandler(c echo.Context) error {
	// Assuming JWT middleware has already validated the token
	return c.JSON(http.StatusOK, map[string]string{"message": "Logout successful"})
}

func ChangePasswordHandler(c echo.Context) error {
	// Extract user ID from JWT (set by JWT middleware)
	userID := c.Get("user_id").(int64)

	// Bind request body
	req := new(ChangePasswordRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	// Fetch user data from the database
	var hashedPassword string
	err := config.DB.Get(&hashedPassword, "SELECT password FROM users WHERE id = ?", userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Check if the old password is correct
	if !utils.CheckPasswordHash(req.OldPassword, hashedPassword) {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "The password you entered is incorrect."})
	}

	// Hash the new password
	newHashedPassword, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Update the user's password in the database
	_, err = config.DB.Exec("UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?", newHashedPassword, userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Update last login
	err = updateLastLogin(userID)
	if err != nil {
		fmt.Println("error updateLastLogin", err)
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Password updated successfully"})
}

func CreateUserAdminHandler(c echo.Context) error {
	req := new(CreateAdminRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	// if err := c.Validate(req); err != nil {
	// 	return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	// }

	// Hash the password
	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Insert the user into the database
	_, err = config.DB.Exec(
		"INSERT INTO users (email, password, role_id, created_at, updated_at) VALUES (?, ?, ?, NOW(), NOW())",
		req.Username, hashedPassword, 0, // Hardcoded role ID for now
	)
	if err != nil {
		fmt.Println("ERROR", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// // Initialize AWS session
	// sess, _ := pkg.InitAWS()

	// // Create S3 client
	// s3Client, _ := pkg.InitS3(sess)

	// err = pkg.CreateBucketFolderEmailUser(s3Client, req.Email)
	// if err != nil {
	// 	return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	// }

	return c.JSON(http.StatusCreated, map[string]string{"message": "User created successfully"})
}

func CreateUserHandler(c echo.Context) error {
	req := new(CreateUserRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	// if err := c.Validate(req); err != nil {
	// 	return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	// }

	// Hash the password
	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Insert the user into the database
	_, err = config.DB.Exec(
		"INSERT INTO users (email, password, role_id, created_at, updated_at) VALUES (?, ?, ?, NOW(), NOW())",
		req.Email, hashedPassword, 1, // Hardcoded role ID for now
	)
	if err != nil {
		fmt.Println("ERROR", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Insert into table generated_email
	_, err = config.DB.Exec(
		"INSERT INTO generated_emails (username, created_at, updated_at) VALUES (?, NOW(), NOW())",
		req.Email, // Hardcoded role ID for now
	)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// // Initialize AWS session
	// sess, _ := pkg.InitAWS()

	// // Create S3 client
	// s3Client, _ := pkg.InitS3(sess)

	// err = pkg.CreateBucketFolderEmailUser(s3Client, req.Email)
	// if err != nil {
	// 	return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	// }

	return c.JSON(http.StatusCreated, map[string]string{"message": "User created successfully"})
}

func BulkCreateUserHandler(c echo.Context) error {
	// Get user ID and email from context
	userID := c.Get("user_id").(int64)

	var emailUser string
	err := config.DB.Get(&emailUser, `
        SELECT email 
        FROM users 
        WHERE id = ? LIMIT 1`, userID)
	if err != nil {
		fmt.Println("Failed to fetch user email", err)
		return err
	}

	req := new(BulkCreateUserRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	if req.BaseName == "" || req.Quantity == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "BaseName and Quantity are required"})
	}

	createdUsers := []map[string]string{}
	skippedUsers := []map[string]string{}

	var names [][]string
	if req.BaseName == "random" {
		// Load names from CSV file
		file, err := os.Open("names.csv")
		if err != nil {
			fmt.Println("Failed to open names.csv", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to open names.csv"})
		}
		defer file.Close()

		reader := csv.NewReader(file)
		names, err = reader.ReadAll()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to read names.csv"})
		}

		// Shuffle the names to ensure randomness
		rand.Seed(uint64(time.Now().UnixNano()))
		rand.Shuffle(len(names), func(i, j int) { names[i], names[j] = names[j], names[i] })
	}

	for i := 0; i < req.Quantity; i++ {
		var username string
		if req.BaseName == "random" {
			if len(names) == 0 {
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "No names available in names.csv"})
			}
			name := names[i%len(names)]
			username = fmt.Sprintf("%s%s@%s", name[0], name[1], req.Domain)
		} else {
			username = fmt.Sprintf("%s@%s", req.BaseName, req.Domain)
			if i > 0 {
				username = fmt.Sprintf("%s%d@%s", req.BaseName, i, req.Domain)
			}
		}

		// Check if username exists
		var exists bool
		err := config.DB.Get(&exists, "SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)", username)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}

		// If username exists, append a number to make it unique
		counter := 1
		originalUsername := strings.Split(username, "@")[0]
		for exists {
			username = fmt.Sprintf("%s%d@%s", originalUsername, counter, req.Domain)
			err := config.DB.Get(&exists, "SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)", username)
			if err != nil {
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
			}
			counter++
		}

		// Start transaction for this user
		tx, err := config.DB.Begin()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		defer tx.Rollback()

		hashedPassword, err := utils.HashPassword(req.Password) // Use a default password or generate one
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}

		// Insert user
		_, err = tx.Exec(
			"INSERT INTO users (email, password, role_id, created_at, updated_at) VALUES (?, ?, 1, NOW(), NOW())",
			username, hashedPassword,
		)
		if err != nil {
			fmt.Println("Failed to insert user", err)
			continue
		}

		// Insert generated email
		_, err = tx.Exec(
			"INSERT INTO generated_emails (username, created_at, updated_at) VALUES (?, NOW(), NOW())",
			username,
		)
		if err != nil {
			fmt.Println("Failed to insert generated email", err)
			continue
		}

		createdUsers = append(createdUsers, map[string]string{
			"No":       fmt.Sprintf("%d", i+1),
			"Email":    username,
			"Password": req.Password, // Use the actual password if generated
		})

		tx.Commit()
	}

	// Generate the email body with enhanced styling
	var emailBody strings.Builder
	emailBody.WriteString(`
        <table style="width: 100%; border-collapse: collapse;">
            <tr style="background-color: #f2f2f2;">
                <th style="border: 1px solid #ddd; padding: 8px;">No</th>
                <th style="border: 1px solid #ddd; padding: 8px;">Email</th>
                <th style="border: 1px solid #ddd; padding: 8px;">Password</th>
            </tr>
    `)

	for i, user := range createdUsers {
		emailBody.WriteString(fmt.Sprintf(`
            <tr>
                <td style="border: 1px solid #ddd; padding: 8px;">%d</td>
                <td style="border: 1px solid #ddd; padding: 8px;">%s</td>
                <td style="border: 1px solid #ddd; padding: 8px;">%s</td>
            </tr>
        `, i+1, user["Email"], user["Password"]))
	}

	emailBody.WriteString("</table>")

	// // Send email via pkg/aws
	// err = pkg.SendEmail(req.SendTo, emailUser, "Mailsaja Create Bulk User", emailBody.String(), nil)
	// if err != nil {
	// 	fmt.Println("Failed to send email", err)
	// 	return c.JSON(http.StatusInternalServerError, map[string]string{
	// 		"error": "Failed to send email",
	// 	})
	// }

	// Return the response
	return c.JSON(http.StatusCreated, map[string]interface{}{
		"message":       fmt.Sprintf("%d users created successfully", len(createdUsers)),
		"created_users": createdUsers,
		"skipped_users": skippedUsers,
		"send_to":       req.SendTo,
		"email_body":    emailBody.String(),
	})
}

// ONLY ADMIN CAN DELETE USER
func DeleteUserHandler(c echo.Context) error {
	userID := c.Param("id")

	// Get user email before deletion for S3
	var userEmail string
	err := config.DB.Get(&userEmail, "SELECT email FROM users WHERE id = ?", userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found"})
	}

	// Start transaction
	tx, err := config.DB.Begin()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to start transaction"})
	}
	defer tx.Rollback()

	// Delete emails
	_, err = tx.Exec("DELETE FROM emails WHERE user_id = ?", userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete emails"})
	}

	// Delete user
	result, err := tx.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete user"})
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found"})
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to commit transaction"})
	}

	// TODO: SEARCH HIS ATTACHMENT AND DELETE IT
	// // Initialize AWS session
	// sess, _ := pkg.InitAWS()
	// s3Client, _ := pkg.InitS3(sess)

	// // Delete S3 folder
	// bucketName := viper.GetString("S3_BUCKET_NAME")
	// prefix := fmt.Sprintf("%s/", userEmail)

	// // List and delete all objects with the user's prefix
	// err = pkg.DeleteS3FolderContents(s3Client, bucketName, prefix)
	// if err != nil {
	// 	fmt.Println("Failed to delete S3 folder:", err)
	// 	return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete user files"})
	// }

	return c.JSON(http.StatusOK, map[string]string{"message": "User and associated data deleted successfully"})
}

func GetUserHandler(c echo.Context) error {
	userID := c.Param("id")

	// Fetch user details by ID
	var user User
	err := config.DB.Get(&user, "SELECT * FROM users WHERE role_id = 1 AND id = ?", userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, user)
}

func GetUserMeHandler(c echo.Context) error {
	// Extract user ID from JWT (set by JWT middleware)
	userID := c.Get("user_id").(int64)

	// Fetch user details by ID
	var user User
	err := config.DB.Get(&user, "SELECT * FROM users WHERE id = ?", userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
	}

	// Update last login
	err = updateLastLogin(user.ID)
	if err != nil {
		fmt.Println("error updateLastLogin", err)
	}

	return c.JSON(http.StatusOK, user)
}

func ListAdminUsersHandler(c echo.Context) error {
	searchUsername := c.QueryParam("email")
	// Fetch paginated users
	var users []User
	query := "SELECT * FROM users WHERE role_id = 0 "
	if searchUsername != "" {
		query = query + " AND email LIKE '%" + searchUsername + "%' "
	}
	query = query + " ORDER BY last_login DESC"
	err := config.DB.Select(&users,
		query)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	response := PaginatedUsers{
		Users: users,
	}

	return c.JSON(http.StatusOK, response)
}

func ListUsersHandler(c echo.Context) error {
	// Get pagination parameters
	page, _ := strconv.Atoi(c.QueryParam("page"))
	pageSize, _ := strconv.Atoi(c.QueryParam("page_size"))
	searchEmail := c.QueryParam("email")

	// Set defaults
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10 // Default page size
	}

	// Calculate offset
	offset := (page - 1) * pageSize

	// Get total count
	var totalCount int
	err := config.DB.Get(&totalCount, "SELECT COUNT(*) FROM users WHERE role_id = 1")
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Fetch paginated users
	var users []User
	query := "SELECT * FROM users WHERE role_id = 1 "
	if searchEmail != "" {
		query = query + " AND email LIKE '%" + searchEmail + "%' "
	}
	query = query + " ORDER BY last_login DESC LIMIT ? OFFSET ?"
	err = config.DB.Select(&users,
		query,
		pageSize, offset)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Calculate total pages
	totalPages := (totalCount + pageSize - 1) / pageSize

	response := PaginatedUsers{
		Users:      users,
		TotalCount: totalCount,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}

	return c.JSON(http.StatusOK, response)
}

func updateLastLogin(userID int64) error {
	// Update the user's last login time
	_, err := config.DB.Exec("UPDATE users SET last_login = ? WHERE id = ?", time.Now(), userID)
	if err != nil {
		return err
	}

	return nil
}
