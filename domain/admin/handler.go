package admin

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Triaksa-Space/be-mail-platform/config"
	"github.com/Triaksa-Space/be-mail-platform/pkg/logger"
	"github.com/Triaksa-Space/be-mail-platform/utils"
	"github.com/labstack/echo/v4"
	"github.com/spf13/viper"
)

// GetDomainPrimary returns the primary domain from config (default: mailria.com)
func GetDomainPrimary() string {
	d := viper.GetString("DOMAIN_PRIMARY")
	if d == "" {
		return "mailria.com"
	}
	return d
}

// GetDomainSecondary returns the secondary domain from config (default: mailsaja.com)
func GetDomainSecondary() string {
	d := viper.GetString("DOMAIN_SECONDARY")
	if d == "" {
		return "mailsaja.com"
	}
	return d
}

// GetOverviewHandler returns the admin dashboard overview
func GetOverviewHandler(c echo.Context) error {
	log := logger.Get().WithComponent("admin_overview")

	// Read all 4 stats from dashboard_counters in a single query
	domainPrimary := GetDomainPrimary()
	domainSecondary := GetDomainSecondary()
	keyPrimary := "users_domain_" + domainPrimary
	keySecondary := "users_domain_" + domainSecondary

	type counterRow struct {
		Key   string `db:"counter_key"`
		Value int64  `db:"counter_value"`
	}
	var counters []counterRow
	err := config.DB.Select(&counters, `
		SELECT counter_key, counter_value FROM dashboard_counters
		WHERE counter_key IN (?, ?, 'total_inbox', 'total_sent')
	`, keyPrimary, keySecondary)
	if err != nil {
		log.Warn("Error reading dashboard counters", logger.Err(err))
	}

	var totalUsersMailria, totalUsersMailsaja, totalInbox, totalSent int64
	for _, ct := range counters {
		switch ct.Key {
		case keyPrimary:
			totalUsersMailria = ct.Value
		case keySecondary:
			totalUsersMailsaja = ct.Value
		case "total_inbox":
			totalInbox = ct.Value
		case "total_sent":
			totalSent = ct.Value
		}
	}

	// Get recent inbox emails with full details
	type InboxRow struct {
		ID             int64          `db:"id"`
		UserID         int64          `db:"user_id"`
		UserEmail      string         `db:"user_email"`
		SenderEmail    string         `db:"sender_email"`
		SenderName     string         `db:"sender_name"`
		Subject        sql.NullString `db:"subject"`
		Preview        sql.NullString `db:"preview"`
		Body           sql.NullString `db:"body"`
		IsRead         bool           `db:"is_read"`
		Attachments    sql.NullString `db:"attachments"`
		Timestamp      time.Time      `db:"timestamp"`
	}
	var inboxRows []InboxRow
	err = config.DB.Select(&inboxRows, `
		SELECT e.id, e.user_id, u.email as user_email,
		       e.sender_email, e.sender_name, e.subject, e.preview, e.body,
		       e.is_read_admin AS is_read, e.attachments, e.timestamp
		FROM emails e
		JOIN users u ON e.user_id = u.id
		ORDER BY e.timestamp DESC
		LIMIT 10
	`)
	if err != nil {
		log.Warn("Error fetching recent inbox", logger.Err(err))
	}

	inboxEmails := make([]OverviewInboxEmail, 0)
	for _, r := range inboxRows {
		subject := ""
		if r.Subject.Valid {
			subject = r.Subject.String
		}
		preview := ""
		if r.Preview.Valid {
			preview = r.Preview.String
		}
		body := ""
		if r.Body.Valid {
			body = r.Body.String
		}
		hasAttachments := false
		if r.Attachments.Valid && r.Attachments.String != "" && r.Attachments.String != "[]" {
			hasAttachments = true
		}

		inboxEmails = append(inboxEmails, OverviewInboxEmail{
			ID:             utils.EncodeID(int(r.ID)),
			UserID:         utils.EncodeID(int(r.UserID)),
			UserEmail:      r.UserEmail,
			From:           r.SenderEmail,
			FromName:       r.SenderName,
			Subject:        subject,
			Preview:        preview,
			Body:           body,
			IsRead:         r.IsRead,
			HasAttachments: hasAttachments,
			ReceivedAt:     r.Timestamp,
		})
	}

	// Get recent sent emails with full details
	type SentRow struct {
		ID          int64          `db:"id"`
		UserID      int64          `db:"user_id"`
		UserEmail   string         `db:"user_email"`
		FromEmail   string         `db:"from_email"`
		ToEmail     string         `db:"to_email"`
		Subject     string         `db:"subject"`
		BodyPreview sql.NullString `db:"body_preview"`
		Body        sql.NullString `db:"body"`
		IsRead      bool           `db:"is_read"`
		Status      string         `db:"status"`
		SentAt      sql.NullTime   `db:"sent_at"`
	}
	var sentRows []SentRow
	err = config.DB.Select(&sentRows, `
		SELECT s.id, s.user_id, u.email as user_email,
		       s.from_email, s.to_email, s.subject, s.body_preview, s.body, s.is_read_admin AS is_read, s.status, s.sent_at
		FROM sent_emails s
		JOIN users u ON s.user_id = u.id
		ORDER BY COALESCE(s.sent_at, s.created_at) DESC
		LIMIT 10
	`)
	if err != nil {
		log.Warn("Error fetching recent sent", logger.Err(err))
	}

	sentEmails := make([]OverviewSentEmail, 0)
	for _, r := range sentRows {
		preview := ""
		if r.BodyPreview.Valid {
			preview = r.BodyPreview.String
		}
		body := ""
		if r.Body.Valid {
			body = r.Body.String
		}
		var sentAt *time.Time
		if r.SentAt.Valid {
			sentAt = &r.SentAt.Time
		}

		sentEmails = append(sentEmails, OverviewSentEmail{
			ID:        utils.EncodeID(int(r.ID)),
			UserID:    utils.EncodeID(int(r.UserID)),
			UserEmail: r.UserEmail,
			From:      r.FromEmail,
			To:        r.ToEmail,
			Subject:   r.Subject,
			Preview:   preview,
			Body:      body,
			IsRead:    r.IsRead,
			Status:    r.Status,
			SentAt:    sentAt,
		})
	}

	response := OverviewResponse{
		Stats: OverviewStats{
			TotalUsersMailria:  totalUsersMailria,
			TotalUsersMailsaja: totalUsersMailsaja,
			TotalInbox:         totalInbox,
			TotalSent:          totalSent,
		},
		Inbox:       inboxEmails,
		Sent:        sentEmails,
		GeneratedAt: time.Now(),
	}

	return c.JSON(http.StatusOK, response)
}

// GetAdminInboxHandler returns all inbox emails for admin view
func GetAdminInboxHandler(c echo.Context) error {
	// Pagination
	page, _ := strconv.Atoi(c.QueryParam("page"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	if limit < 1 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}
	offset := (page - 1) * limit

	// Filters
	dateFrom := c.QueryParam("date_from")
	dateTo := c.QueryParam("date_to")
	search := c.QueryParam("search")
	userIDParam := c.QueryParam("user_id")
	isReadParam := c.QueryParam("is_read")

	// Build query
	var args []interface{}
	whereClause := "1=1"

	if dateFrom != "" {
		whereClause += " AND e.timestamp >= ?"
		args = append(args, dateFrom+" 00:00:00")
	}
	if dateTo != "" {
		whereClause += " AND e.timestamp <= ?"
		args = append(args, dateTo+" 23:59:59")
	}
	if search != "" {
		whereClause += " AND (e.sender_email LIKE ? OR e.sender_name LIKE ? OR e.subject LIKE ?)"
		searchPattern := "%" + search + "%"
		args = append(args, searchPattern, searchPattern, searchPattern)
	}
	if userIDParam != "" {
		userID, err := utils.DecodeID(userIDParam)
		if err == nil {
			whereClause += " AND e.user_id = ?"
			args = append(args, userID)
		}
	}
	if isReadParam != "" {
		isRead := isReadParam == "true"
		whereClause += " AND e.is_read_admin = ?"
		args = append(args, isRead)
	}

	// Get total count
	var total int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM emails e JOIN users u ON e.user_id = u.id WHERE %s", whereClause)
	err := config.DB.Get(&total, countQuery, args...)
	if err != nil {
		fmt.Println("Error counting inbox:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Get emails
	args = append(args, limit, offset)
	query := fmt.Sprintf(`
		SELECT e.id, e.user_id, u.email as user_email, e.sender_email, e.sender_name, e.subject, e.preview, e.is_read_admin AS is_read,
		       CASE WHEN e.attachments IS NOT NULL AND e.attachments != '' AND e.attachments != '[]' THEN 1 ELSE 0 END as has_attachments,
		       e.timestamp
		FROM emails e
		JOIN users u ON e.user_id = u.id
		WHERE %s
		ORDER BY e.timestamp DESC
		LIMIT ? OFFSET ?
	`, whereClause)

	var emails []AdminInboxEmail
	err = config.DB.Select(&emails, query, args...)
	if err != nil {
		fmt.Println("Error fetching inbox:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Build response
	data := make([]AdminInboxEmailResponse, 0)
	for _, e := range emails {
		subject := ""
		if e.Subject.Valid {
			subject = e.Subject.String
		}
		preview := ""
		if e.Preview.Valid {
			preview = e.Preview.String
		}
		data = append(data, AdminInboxEmailResponse{
			ID:             utils.EncodeID(int(e.ID)),
			UserID:         utils.EncodeID(int(e.UserID)),
			UserEmail:      e.UserEmail,
			From:           e.SenderEmail,
			FromName:       e.SenderName,
			Subject:        subject,
			Preview:        preview,
			IsRead:         e.IsRead,
			HasAttachments: e.HasAttachments,
			ReceivedAt:     e.Timestamp,
		})
	}

	totalPages := (total + limit - 1) / limit

	return c.JSON(http.StatusOK, AdminInboxResponse{
		Data: data,
		Pagination: PaginationResponse{
			Page:       page,
			Limit:      limit,
			Total:      total,
			TotalPages: totalPages,
		},
	})
}

// GetAdminInboxDetailHandler returns a single inbox email detail for admin view
func GetAdminInboxDetailHandler(c echo.Context) error {
	log := logger.Get().WithComponent("admin_inbox_detail")

	// Decode email ID
	emailIDParam := c.Param("id")
	emailID, err := utils.DecodeID(emailIDParam)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid email ID",
		})
	}

	// Get inbox email from database
	type InboxEmailDetail struct {
		ID          int64          `db:"id"`
		UserID      int64          `db:"user_id"`
		UserEmail   string         `db:"user_email"`
		SenderEmail string         `db:"sender_email"`
		SenderName  string         `db:"sender_name"`
		Subject     sql.NullString `db:"subject"`
		Preview     sql.NullString `db:"preview"`
		Body        sql.NullString `db:"body"`
		Attachments sql.NullString `db:"attachments"`
		IsRead      bool           `db:"is_read"`
		Timestamp   time.Time      `db:"timestamp"`
		CreatedAt   time.Time      `db:"created_at"`
	}

	var email InboxEmailDetail
	err = config.DB.Get(&email, `
		SELECT e.id, e.user_id, u.email as user_email,
		       e.sender_email, e.sender_name, e.subject, e.preview, e.body,
		       e.attachments, e.is_read_admin AS is_read, e.timestamp, e.created_at
		FROM emails e
		JOIN users u ON e.user_id = u.id
		WHERE e.id = ?
	`, emailID)

	if err != nil {
		if err == sql.ErrNoRows {
			return c.JSON(http.StatusNotFound, map[string]string{
				"error": "Email not found",
			})
		}
		fmt.Println("Error fetching inbox email detail:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Internal server error",
		})
	}

	if !email.IsRead {
		if _, err := config.DB.Exec(`UPDATE emails SET is_read_admin = TRUE WHERE id = ?`, emailID); err != nil {
			log.Warn("Failed to mark admin email as read", logger.Err(err), logger.Int("email_id", emailID))
		} else {
			email.IsRead = true
		}
	}

	// Build response
	subject := ""
	if email.Subject.Valid {
		subject = email.Subject.String
	}
	preview := ""
	if email.Preview.Valid {
		preview = email.Preview.String
	}
	body := ""
	if email.Body.Valid {
		body = email.Body.String
	}
	attachments := ""
	if email.Attachments.Valid {
		attachments = email.Attachments.String
	}
	hasAttachments := attachments != "" && attachments != "[]"

	response := map[string]interface{}{
		"id":              utils.EncodeID(int(email.ID)),
		"user_id":         utils.EncodeID(int(email.UserID)),
		"user_email":      email.UserEmail,
		"from":            email.SenderEmail,
		"from_name":       email.SenderName,
		"subject":         subject,
		"preview":         preview,
		"body":            body,
		"attachments":     attachments,
		"is_read":         email.IsRead,
		"has_attachments": hasAttachments,
		"received_at":     email.Timestamp,
		"created_at":      email.CreatedAt,
	}

	return c.JSON(http.StatusOK, response)
}

// GetAdminSentHandler returns all sent emails for admin view
func GetAdminSentHandler(c echo.Context) error {
	// Pagination
	page, _ := strconv.Atoi(c.QueryParam("page"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	if limit < 1 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}
	offset := (page - 1) * limit

	// Filters
	dateFrom := c.QueryParam("date_from")
	dateTo := c.QueryParam("date_to")
	fromEmail := c.QueryParam("from")
	toEmail := c.QueryParam("to")
	subject := c.QueryParam("subject")
	status := c.QueryParam("status")
	isReadParam := c.QueryParam("is_read")

	// Build query
	var args []interface{}
	whereClause := "1=1"

	if dateFrom != "" {
		whereClause += " AND (s.sent_at >= ? OR s.created_at >= ?)"
		args = append(args, dateFrom+" 00:00:00", dateFrom+" 00:00:00")
	}
	if dateTo != "" {
		whereClause += " AND (s.sent_at <= ? OR s.created_at <= ?)"
		args = append(args, dateTo+" 23:59:59", dateTo+" 23:59:59")
	}
	if fromEmail != "" {
		whereClause += " AND s.from_email LIKE ?"
		args = append(args, "%"+fromEmail+"%")
	}
	if toEmail != "" {
		whereClause += " AND s.to_email LIKE ?"
		args = append(args, "%"+toEmail+"%")
	}
	if subject != "" {
		whereClause += " AND s.subject LIKE ?"
		args = append(args, "%"+subject+"%")
	}
	if status != "" {
		whereClause += " AND s.status = ?"
		args = append(args, status)
	}
	if isReadParam != "" {
		isRead := isReadParam == "true"
		whereClause += " AND s.is_read_admin = ?"
		args = append(args, isRead)
	}

	// Get total count
	var total int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sent_emails s JOIN users u ON s.user_id = u.id WHERE %s", whereClause)
	err := config.DB.Get(&total, countQuery, args...)
	if err != nil {
		fmt.Println("Error counting sent:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Get sent emails
	args = append(args, limit, offset)
	query := fmt.Sprintf(`
		SELECT s.id, s.user_id, u.email as user_email, s.from_email, s.to_email, s.subject, s.body_preview, s.is_read_admin AS is_read, s.status, s.provider, s.sent_at, s.created_at
		FROM sent_emails s
		JOIN users u ON s.user_id = u.id
		WHERE %s
		ORDER BY COALESCE(s.sent_at, s.created_at) DESC
		LIMIT ? OFFSET ?
	`, whereClause)

	var emails []AdminSentEmail
	err = config.DB.Select(&emails, query, args...)
	if err != nil {
		fmt.Println("Error fetching sent:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Build response
	data := make([]AdminSentEmailResponse, 0)
	for _, e := range emails {
		bodyPreview := ""
		if e.BodyPreview.Valid {
			bodyPreview = e.BodyPreview.String
		}
		provider := ""
		if e.Provider.Valid {
			provider = e.Provider.String
		}
		var sentAt *time.Time
		if e.SentAt.Valid {
			sentAt = &e.SentAt.Time
		}
		data = append(data, AdminSentEmailResponse{
			ID:          utils.EncodeID(int(e.ID)),
			UserID:      utils.EncodeID(int(e.UserID)),
			UserEmail:   e.UserEmail,
			From:        e.FromEmail,
			To:          e.ToEmail,
			Subject:     e.Subject,
			BodyPreview: bodyPreview,
			IsRead:      e.IsRead,
			Status:      e.Status,
			Provider:    provider,
			SentAt:      sentAt,
		})
	}

	totalPages := (total + limit - 1) / limit

	return c.JSON(http.StatusOK, AdminSentResponse{
		Data: data,
		Pagination: PaginationResponse{
			Page:       page,
			Limit:      limit,
			Total:      total,
			TotalPages: totalPages,
		},
	})
}

// GetAdminSentDetailHandler returns a single sent email detail for admin view
func GetAdminSentDetailHandler(c echo.Context) error {
	log := logger.Get().WithComponent("admin_sent_detail")

	// Decode email ID
	emailIDParam := c.Param("id")
	emailID, err := utils.DecodeID(emailIDParam)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid email ID",
		})
	}

	// Get sent email from database
	type SentEmailDetail struct {
		ID          int64          `db:"id"`
		UserID      int64          `db:"user_id"`
		UserEmail   string         `db:"user_email"`
		FromEmail   string         `db:"from_email"`
		ToEmail     string         `db:"to_email"`
		Subject     string         `db:"subject"`
		BodyPreview sql.NullString `db:"body_preview"`
		Body        sql.NullString `db:"body"`
		Attachments sql.NullString `db:"attachments"`
		Provider    sql.NullString `db:"provider"`
		IsRead      bool           `db:"is_read"`
		Status      string         `db:"status"`
		SentAt      sql.NullTime   `db:"sent_at"`
		CreatedAt   time.Time      `db:"created_at"`
	}

	var email SentEmailDetail
	err = config.DB.Get(&email, `
		SELECT s.id, s.user_id, u.email as user_email,
		       s.from_email, s.to_email, s.subject, s.body_preview, s.body,
		       s.attachments, s.provider, s.is_read_admin AS is_read, s.status, s.sent_at, s.created_at
		FROM sent_emails s
		JOIN users u ON s.user_id = u.id
		WHERE s.id = ?
	`, emailID)

	if err != nil {
		if err == sql.ErrNoRows {
			return c.JSON(http.StatusNotFound, map[string]string{
				"error": "Email not found",
			})
		}
		fmt.Println("Error fetching sent email detail:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Internal server error",
		})
	}

	if !email.IsRead {
		if _, err := config.DB.Exec(`UPDATE sent_emails SET is_read_admin = TRUE WHERE id = ?`, emailID); err != nil {
			log.Warn("Failed to mark admin sent email as read", logger.Err(err), logger.Int("email_id", emailID))
		} else {
			email.IsRead = true
		}
	}

	// Build response
	bodyPreview := ""
	if email.BodyPreview.Valid {
		bodyPreview = email.BodyPreview.String
	}
	body := ""
	if email.Body.Valid {
		body = email.Body.String
	}
	attachments := ""
	if email.Attachments.Valid {
		attachments = email.Attachments.String
	}
	provider := ""
	if email.Provider.Valid {
		provider = email.Provider.String
	}
	var sentAt *time.Time
	if email.SentAt.Valid {
		sentAt = &email.SentAt.Time
	}

	response := map[string]interface{}{
		"id":           utils.EncodeID(int(email.ID)),
		"user_id":      utils.EncodeID(int(email.UserID)),
		"user_email":   email.UserEmail,
		"from":         email.FromEmail,
		"to":           email.ToEmail,
		"subject":      email.Subject,
		"body_preview": bodyPreview,
		"body":         body,
		"attachments":  attachments,
		"provider":     provider,
		"is_read":      email.IsRead,
		"status":       email.Status,
		"sent_at":      sentAt,
		"created_at":   email.CreatedAt,
	}

	return c.JSON(http.StatusOK, response)
}

// GetMenusHandler returns accessible menus for the current user
func GetMenusHandler(c echo.Context) error {
	roleID := c.Get("role_id").(int64)

	var menus []AdminMenu
	err := config.DB.Select(&menus, `
		SELECT m.id, m.menu_key, m.menu_name, m.parent_id, m.sort_order, m.icon, m.route
		FROM admin_menus m
		JOIN role_menu_permissions rmp ON m.id = rmp.menu_id
		WHERE rmp.role_id = ? AND rmp.can_view = TRUE
		ORDER BY m.sort_order
	`, roleID)

	if err != nil {
		fmt.Println("Error fetching menus:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	menuResponses := make([]MenuResponse, 0)
	for _, m := range menus {
		route := ""
		if m.Route.Valid {
			route = m.Route.String
		}
		icon := ""
		if m.Icon.Valid {
			icon = m.Icon.String
		}
		menuResponses = append(menuResponses, MenuResponse{
			Key:   m.MenuKey,
			Name:  m.MenuName,
			Route: route,
			Icon:  icon,
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"menus": menuResponses,
	})
}

// GetPermissionsHandler returns all permissions (SuperAdmin only)
func GetPermissionsHandler(c echo.Context) error {
	// Get all roles with their permissions
	type RoleMenus struct {
		RoleID  int    `db:"role_id"`
		MenuKey string `db:"menu_key"`
	}
	var roleMenus []RoleMenus
	err := config.DB.Select(&roleMenus, `
		SELECT rmp.role_id, m.menu_key
		FROM role_menu_permissions rmp
		JOIN admin_menus m ON rmp.menu_id = m.id
		WHERE rmp.can_view = TRUE
		ORDER BY rmp.role_id, m.sort_order
	`)
	if err != nil {
		fmt.Println("Error fetching permissions:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Group by role
	roleMap := make(map[int][]string)
	for _, rm := range roleMenus {
		roleMap[rm.RoleID] = append(roleMap[rm.RoleID], rm.MenuKey)
	}

	// Build response
	roles := make([]RolePermissionsResponse, 0)
	for roleID := range RoleNames {
		if roleID == 1 { // Skip User role
			continue
		}
		roles = append(roles, RolePermissionsResponse{
			RoleID:   roleID,
			RoleName: RoleNames[roleID],
			Menus:    roleMap[roleID],
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"roles": roles,
	})
}

// UpdatePermissionsHandler updates permissions for a role (SuperAdmin only)
func UpdatePermissionsHandler(c echo.Context) error {
	roleIDParam := c.Param("role_id")
	roleID, err := strconv.Atoi(roleIDParam)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":   "invalid_role_id",
			"message": "Invalid role ID",
		})
	}

	// Can't modify SuperAdmin or User permissions
	if roleID == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":   "forbidden",
			"message": "Cannot modify SuperAdmin permissions",
		})
	}
	if roleID == 1 {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":   "forbidden",
			"message": "Cannot modify User role permissions",
		})
	}

	req := new(UpdatePermissionsRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	// Start transaction
	tx, err := config.DB.Begin()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}
	defer tx.Rollback()

	// Delete existing permissions for this role
	_, err = tx.Exec("DELETE FROM role_menu_permissions WHERE role_id = ?", roleID)
	if err != nil {
		fmt.Println("Error deleting existing permissions:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Insert new permissions
	for _, perm := range req.Permissions {
		// Get menu ID
		var menuID int64
		err = config.DB.Get(&menuID, "SELECT id FROM admin_menus WHERE menu_key = ?", perm.MenuKey)
		if err != nil {
			fmt.Println("Error finding menu:", perm.MenuKey, err)
			continue
		}

		_, err = tx.Exec(`
			INSERT INTO role_menu_permissions (role_id, menu_id, can_view, can_create, can_edit, can_delete)
			VALUES (?, ?, ?, ?, ?, ?)
		`, roleID, menuID, perm.CanView, perm.CanCreate, perm.CanEdit, perm.CanDelete)
		if err != nil {
			fmt.Println("Error inserting permission:", err)
			continue
		}
	}

	if err := tx.Commit(); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Permissions updated successfully",
	})
}

// IncrementCounter increments a dashboard counter
func IncrementCounter(key string, delta int64) error {
	_, err := config.DB.Exec(`
		UPDATE dashboard_counters
		SET counter_value = counter_value + ?, updated_at = NOW()
		WHERE counter_key = ?
	`, delta, key)
	return err
}

// GetCounter retrieves a counter value
func GetCounter(key string) (int64, error) {
	var value int64
	err := config.DB.Get(&value, `
		SELECT counter_value FROM dashboard_counters WHERE counter_key = ?
	`, key)
	return value, err
}

// ReconcileCountersHandler re-queries actual data from DB and corrects all dashboard counters
func ReconcileCountersHandler(c echo.Context) error {
	log := logger.Get().WithComponent("admin_reconcile")

	// Count total_inbox
	var totalInbox int64
	if err := config.DB.Get(&totalInbox, "SELECT COUNT(*) FROM emails WHERE email_type = 'inbox'"); err != nil {
		log.Error("Failed to count inbox emails", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to reconcile counters"})
	}

	// Count total_sent
	var totalSent int64
	if err := config.DB.Get(&totalSent, "SELECT COUNT(*) FROM emails WHERE email_type = 'sent'"); err != nil {
		log.Error("Failed to count sent emails", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to reconcile counters"})
	}

	// Count users by domain
	type DomainCount struct {
		Domain string `db:"domain"`
		Count  int64  `db:"count"`
	}
	var domainCounts []DomainCount
	err := config.DB.Select(&domainCounts, `
		SELECT SUBSTRING_INDEX(email, '@', -1) as domain, COUNT(*) as count
		FROM users
		WHERE role_id = 1
		GROUP BY domain
	`)
	if err != nil {
		log.Error("Failed to count users by domain", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to reconcile counters"})
	}

	// Build updates map and apply
	updates := map[string]int64{
		"total_inbox": totalInbox,
		"total_sent":  totalSent,
	}
	for _, dc := range domainCounts {
		updates["users_domain_"+strings.ToLower(dc.Domain)] = dc.Count
	}

	for key, value := range updates {
		if _, err := config.DB.Exec(`
			UPDATE dashboard_counters
			SET counter_value = ?, updated_at = NOW()
			WHERE counter_key = ?
		`, value, key); err != nil {
			log.Error("Failed to update counter "+key, err)
		}
	}

	log.Info("Counter reconciliation completed")
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":  "Counters reconciled successfully",
		"counters": updates,
	})
}

// InitializeDomainCounters initializes domain counters based on existing users
func InitializeDomainCounters() error {
	type DomainCount struct {
		Domain string `db:"domain"`
		Count  int64  `db:"count"`
	}
	var domainCounts []DomainCount
	err := config.DB.Select(&domainCounts, `
		SELECT SUBSTRING_INDEX(email, '@', -1) as domain, COUNT(*) as count
		FROM users
		WHERE role_id = 1
		GROUP BY domain
	`)
	if err != nil {
		return err
	}

	for _, dc := range domainCounts {
		key := "users_domain_" + strings.ToLower(dc.Domain)
		// Insert or update
		_, err = config.DB.Exec(`
			INSERT INTO dashboard_counters (counter_key, counter_value, updated_at)
			VALUES (?, ?, NOW())
			ON DUPLICATE KEY UPDATE counter_value = ?, updated_at = NOW()
		`, key, dc.Count, dc.Count)
		if err != nil {
			fmt.Println("Error initializing counter for domain:", dc.Domain, err)
		}
	}

	return nil
}
