# Mailria Backend Documentation

> A comprehensive Go backend for the Mailria email platform, supporting multi-domain email management with AWS SES/S3 and Resend integration.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Architecture Overview](#architecture-overview)
3. [Project Structure](#project-structure)
4. [Database Schema](#database-schema)
5. [API Reference](#api-reference)
6. [Business Logic](#business-logic)
7. [Third-Party Integrations](#third-party-integrations)
8. [Background Jobs](#background-jobs)
9. [Authentication & Authorization](#authentication--authorization)
10. [Configuration](#configuration)
11. [Deployment](#deployment)
12. [Troubleshooting](#troubleshooting)
13. [QA Testing](#qa-testing)

---

## Quick Start

### Prerequisites

- **Go 1.23+** installed
- **MySQL 8.0+** database
- **AWS Account** with SES and S3 access
- **Resend Account** for outgoing emails

### Installation

```bash
# Clone the repository
git clone https://github.com/Triaksa-Space/be-mail-platform.git
cd be-mail-platform

# Copy environment template
cp .env.example .env

# Edit .env with your credentials (see Configuration section)

# Install dependencies
go mod download

# Run database migrations
goose -dir migrations mysql "root:password!@tcp(localhost:3306)/mailria?parseTime=true" up

# Start the server
go run cmd/main.go server
```

### Running All Services

The backend requires 3 processes for full functionality:

```bash
# Terminal 1: HTTP Server (port 8000)
go run cmd/main.go server

# Terminal 2: Incoming Email Sync (every 10 seconds)
go run cmd/main.go sync

# Terminal 3: Sent Email Cleanup (every 24 hours)
go run cmd/main.go sync_sent
```

### Production (PM2)

```bash
# Build
go build -o build/main cmd/main.go

# Start all services
pm2 start ./build/main --name "go-server" -- server
pm2 start ./build/main --name "go-sync" -- sync
pm2 start ./build/main --name "go-sync-sent" -- sync_sent
```

---

## Architecture Overview

### High-Level Architecture

```
                                    ┌─────────────────┐
                                    │   Frontend      │
                                    │   (Next.js)     │
                                    └────────┬────────┘
                                             │
                                             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           Go Backend (Echo Framework)                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐               │
│  │   Routes     │───▶│  Middleware  │───▶│   Handlers   │               │
│  │ (route.go)   │    │ (auth, role) │    │  (domain/*)  │               │
│  └──────────────┘    └──────────────┘    └──────┬───────┘               │
│                                                  │                       │
│                      ┌───────────────────────────┼───────────────────┐  │
│                      │                           │                   │  │
│                      ▼                           ▼                   ▼  │
│              ┌──────────────┐           ┌──────────────┐    ┌──────────┐│
│              │   Database   │           │     AWS      │    │  Resend  ││
│              │   (MySQL)    │           │  (SES/S3)    │    │   API    ││
│              └──────────────┘           └──────────────┘    └──────────┘│
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                         Background Jobs                                  │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────┐              ┌─────────────────────┐           │
│  │   sync (10 sec)     │              │  sync_sent (24 hr)  │           │
│  │  - Fetch S3 emails  │              │  - Delete old sent  │           │
│  │  - Store in DB      │              │  - Cleanup S3       │           │
│  └─────────────────────┘              └─────────────────────┘           │
└─────────────────────────────────────────────────────────────────────────┘
```

### Layered Architecture

```
┌─────────────────────────────────────────────────┐
│              HTTP Layer (Echo)                   │
│         routes/route.go - API endpoints          │
├─────────────────────────────────────────────────┤
│              Middleware Layer                    │
│    middleware/auth.go - JWT validation           │
│    middleware/role.go - RBAC                     │
│    middleware/rate_limiter.go - Brute force      │
├─────────────────────────────────────────────────┤
│              Handler Layer                       │
│    domain/email/handler.go - Email logic         │
│    domain/user/handler.go - User management      │
│    domain/domain_email/handler.go - Domains      │
├─────────────────────────────────────────────────┤
│              Integration Layer                   │
│    pkg/aws.go - AWS SES & S3                     │
│    pkg/resend.go - Resend API                    │
│    pkg/smtp.go - SMTP/Haraka                     │
├─────────────────────────────────────────────────┤
│              Data Layer                          │
│    config/config.go - Database connection        │
│    MySQL via sqlx                                │
└─────────────────────────────────────────────────┘
```

---

## Project Structure

```
be-mail-platform/
├── cmd/
│   └── main.go                 # Entry point (server, sync, sync_sent)
│
├── config/
│   └── config.go               # Database & Viper configuration
│
├── domain/
│   ├── email/
│   │   ├── handler.go          # Email handlers (~2490 lines)
│   │   └── model.go            # Email models & types
│   ├── user/
│   │   ├── handler.go          # User handlers (login, CRUD)
│   │   └── model.go            # User models (includes name list)
│   └── domain_email/
│       ├── handler.go          # Domain handlers
│       └── model.go            # Domain models
│
├── middleware/
│   ├── auth.go                 # JWT authentication middleware
│   ├── role.go                 # Role-based access control
│   └── rate_limiter.go         # Login rate limiting
│
├── pkg/
│   ├── aws.go                  # AWS SES & S3 integration (~510 lines)
│   ├── resend.go               # Resend email API client
│   ├── smtp.go                 # SMTP/Haraka client
│   └── sns.go                  # AWS SNS webhook verification
│
├── routes/
│   └── route.go                # All route definitions
│
├── utils/
│   ├── hashing.go              # Password hashing & ID encoding
│   ├── helper.go               # Domain checking utilities
│   └── jwt.go                  # JWT token generation
│
├── migrations/                 # Goose SQL migrations
│   ├── 20241124115216_create_users_table.sql
│   ├── 20241124115217_create_emails_table.sql
│   ├── 20241129030147_create_domains_table.sql
│   ├── 20241203075138_create_incoming_emails_table.sql
│   └── 20241210145941_create_user_login_attempts_table.sql
│
├── scripts/
│   └── seeder.go               # Database seeding
│
├── .env.example                # Environment template
├── go.mod                      # Go module definition
└── go.sum                      # Dependency checksums
```

---

## Database Schema

### Entity Relationship Diagram

```
┌─────────────────────┐         ┌─────────────────────┐
│       users         │         │       emails        │
├─────────────────────┤         ├─────────────────────┤
│ id (PK)             │◄────────│ user_id (FK)        │
│ email (UNIQUE)      │         │ id (PK)             │
│ password            │         │ sender_email        │
│ role_id             │         │ sender_name         │
│ last_login          │         │ subject             │
│ sent_emails         │         │ preview             │
│ last_email_time     │         │ body (LONGBLOB)     │
│ created_by          │         │ attachments (JSON)  │
│ created_at          │         │ email_type          │
│ updated_at          │         │ message_id          │
└─────────────────────┘         │ is_read             │
                                │ timestamp           │
┌─────────────────────┐         │ created_at          │
│ user_login_attempts │         └─────────────────────┘
├─────────────────────┤
│ username (PK)       │         ┌─────────────────────┐
│ failed_attempts     │         │   incoming_emails   │
│ last_attempt_time   │         ├─────────────────────┤
│ blocked_until       │         │ id (PK)             │
└─────────────────────┘         │ message_id (UNIQUE) │
                                │ email_send_to       │
┌─────────────────────┐         │ email_data (BLOB)   │
│      domains        │         │ email_date          │
├─────────────────────┤         │ processed           │
│ id (PK)             │         │ processed_at        │
│ domain              │         │ created_at          │
│ created_at          │         └─────────────────────┘
│ updated_at          │
└─────────────────────┘
```

### Table Details

#### `users`
| Column | Type | Description |
|--------|------|-------------|
| `id` | BIGINT | Primary key, auto-increment |
| `email` | VARCHAR(255) | Unique email address (e.g., user@mailria.com) |
| `password` | VARCHAR(255) | bcrypt hashed password |
| `role_id` | BIGINT | 0=SuperAdmin, 1=User, 2=Admin |
| `last_login` | DATETIME | Last login timestamp |
| `sent_emails` | INT | Daily email counter (max 3) |
| `last_email_time` | TIMESTAMP | Last email sent time (for rate limiting) |
| `created_by` | BIGINT | ID of user who created this account |
| `created_at` | DATETIME | Creation timestamp |
| `updated_at` | DATETIME | Last update timestamp |

#### `emails`
| Column | Type | Description |
|--------|------|-------------|
| `id` | BIGINT | Primary key, auto-increment |
| `user_id` | BIGINT | Foreign key to users table |
| `sender_email` | VARCHAR(255) | Sender's email address |
| `sender_name` | VARCHAR(255) | Sender's display name |
| `subject` | VARCHAR(255) | Email subject line |
| `preview` | VARCHAR(255) | First 25 chars of body |
| `body` | LONGBLOB | Full email body (HTML/text) |
| `attachments` | LONGTEXT | JSON array of S3 URLs |
| `email_type` | VARCHAR(255) | "inbox", "sent", or "bounce" |
| `message_id` | VARCHAR(255) | Provider message ID |
| `is_read` | BOOLEAN | Read status flag |
| `timestamp` | DATETIME | Original email timestamp |

#### `incoming_emails` (Temporary Processing Table)
| Column | Type | Description |
|--------|------|-------------|
| `id` | BIGINT | Primary key |
| `message_id` | VARCHAR(255) | S3 object key (unique) |
| `email_send_to` | VARCHAR(255) | Recipient email |
| `email_data` | LONGBLOB | Raw .eml content |
| `email_date` | DATETIME | Email date from headers |
| `processed` | BOOLEAN | Processing status |
| `processed_at` | DATETIME | When processed |

#### `user_login_attempts`
| Column | Type | Description |
|--------|------|-------------|
| `username` | VARCHAR(255) | Email address (primary key) |
| `failed_attempts` | INT | Count of failed attempts |
| `last_attempt_time` | TIMESTAMP | Last attempt timestamp |
| `blocked_until` | TIMESTAMP | Block expiry time (null if not blocked) |

---

## API Reference

### Authentication

#### Login
```http
POST /login
Content-Type: application/json

{
  "email": "user@mailria.com",
  "password": "password123"
}

Response (200):
{
  "token": "eyJhbGciOiJIUzI1NiIs..."
}

Response (401):
{
  "error": "Invalid email or password"
}

Response (429):
{
  "error": "Too many failed login attempts. Account locked for 5 minutes."
}
```

#### Logout
```http
POST /logout
Authorization: Bearer <token>

Response (200):
{
  "message": "Logout successful"
}
```

---

### User Management

#### Create User (Admin)
```http
POST /user/
Authorization: Bearer <token>
Content-Type: application/json

{
  "email": "newuser",
  "domain": "mailria.com",
  "password": "password123"
}

Response (201):
{
  "id": "encoded_id",
  "email": "newuser@mailria.com"
}
```

#### Bulk Create Users (Admin)
```http
POST /user/bulk
Authorization: Bearer <token>
Content-Type: application/json

{
  "base_name": "john",
  "domain": "mailria.com",
  "password": "SecurePass123",
  "quantity": 10,
  "send_to": "admin@example.com"
}

Response (200):
{
  "message": "Created 10 users",
  "users": [
    {"email": "johnsmith1@mailria.com", "password": "..."},
    ...
  ]
}
```

#### List Users (Admin)
```http
GET /user/?page=1&limit=10&search=john
Authorization: Bearer <token>

Response (200):
{
  "users": [...],
  "total": 100,
  "page": 1,
  "limit": 10
}
```

#### Get Current User
```http
GET /user/get_user_me
Authorization: Bearer <token>

Response (200):
{
  "id": "encoded_id",
  "email": "user@mailria.com",
  "role_id": 1
}
```

#### Change Password
```http
PUT /user/change_password
Authorization: Bearer <token>
Content-Type: application/json

{
  "old_password": "oldpass",
  "new_password": "newpass"
}

Response (200):
{
  "message": "Password updated successfully"
}
```

#### Delete User (Admin)
```http
DELETE /user/:id
Authorization: Bearer <token>

Response (200):
{
  "message": "User deleted successfully"
}
```

---

### Email Operations

#### Send Email (via Resend - Recommended)
```http
POST /email/send/resend
Authorization: Bearer <token>
Content-Type: application/json

{
  "to": "recipient@example.com",
  "subject": "Hello",
  "body": "<p>Email content here</p>",
  "attachments": [
    "https://s3.amazonaws.com/.../file1.pdf",
    "https://s3.amazonaws.com/.../file2.jpg"
  ]
}

Response (200):
{
  "message": "Email sent successfully"
}

Response (429):
{
  "error": "Email limit exceeded"
}
```

#### Upload Attachment
```http
POST /email/upload/attachment
Authorization: Bearer <token>
Content-Type: multipart/form-data

file: <binary>

Response (200):
{
  "url": "https://s3.amazonaws.com/bucket/attachments/user/filename.pdf"
}
```

#### Delete Attachment
```http
POST /email/delete-attachment
Authorization: Bearer <token>
Content-Type: application/json

{
  "url": ["https://s3.amazonaws.com/.../file.pdf"]
}

Response (200):
{
  "message": "Attachment deleted successfully"
}
```

#### Get User Inbox
```http
GET /email/by_user
Authorization: Bearer <token>

Response (200):
{
  "emails": [
    {
      "id": "encoded_id",
      "sender_email": "sender@example.com",
      "sender_name": "John Doe",
      "subject": "Hello",
      "preview": "This is a preview...",
      "is_read": false,
      "timestamp": "2024-01-15T10:30:00Z"
    }
  ]
}
```

#### Get Email Detail
```http
GET /email/by_user/detail/:id
Authorization: Bearer <token>

Response (200):
{
  "id": "encoded_id",
  "sender_email": "sender@example.com",
  "sender_name": "John Doe",
  "subject": "Hello",
  "body": "<p>Full email content</p>",
  "attachments": ["url1", "url2"],
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Get Sent Emails
```http
GET /email/sent/by_user
Authorization: Bearer <token>

Response (200):
{
  "emails": [...]
}
```

#### Download Attachment
```http
POST /email/by_user/download/file
Authorization: Bearer <token>
Content-Type: application/json

{
  "url": "https://s3.amazonaws.com/.../file.pdf"
}

Response: Binary file download
```

---

### Domain Management (SuperAdmin)

#### Get Domains
```http
GET /domain/dropdown
Authorization: Bearer <token>

Response (200):
{
  "domains": [
    {"id": 1, "domain": "mailria.com"},
    {"id": 2, "domain": "mailsaja.com"}
  ]
}
```

#### Create Domain
```http
POST /
Authorization: Bearer <token>
Content-Type: application/json

{
  "domain": "newdomain.com"
}
```

#### Delete Domain
```http
DELETE /:id
Authorization: Bearer <token>
```

---

### Admin Endpoints

#### List All Emails (Admin)
```http
GET /email/
Authorization: Bearer <token>
```

#### View User's Inbox (Admin)
```http
GET /email/by_user/:user_id
Authorization: Bearer <token>
```

#### Delete Email (Admin)
```http
DELETE /email/:id
Authorization: Bearer <token>
```

#### Manual Sync (Admin)
```http
GET /email/bucket/sync
Authorization: Bearer <token>

Response (200):
{
  "total_emails": 50,
  "new_emails": 10,
  "failed_emails": 2,
  "skipped_emails": 0
}
```

---

### Webhook Endpoint

#### Email Bounce Handler
```http
POST /email/bounce
Content-Type: application/json

{
  "type": "email.bounced",
  "created_at": "2024-01-15 10:30:00+00",
  "data": {
    "from": "user@mailria.com",
    "to": ["recipient@example.com"],
    "subject": "Original subject",
    "email_id": "message-uuid",
    "bounce": {
      "message": "Address not found"
    }
  }
}
```

---

## Business Logic

### Email Sending Limits

**Rule**: Each user can send maximum **3 emails per 24 hours**.

**Implementation** (`domain/email/handler.go:193-228`):

```go
func CheckEmailLimit(userID int64) error {
    // 1. Fetch user's sent_emails count and last_email_time
    // 2. If sent_emails >= 3:
    //    - Check if 24h has passed since last_email_time
    //    - If yes: Reset counter to 0
    //    - If no: Return "daily email limit exceeded"
    // 3. After successful send: Increment sent_emails counter
}
```

**Flow Diagram**:
```
User Sends Email
      │
      ▼
Check sent_emails >= 3?
      │
  ┌───┴───┐
  │ Yes   │ No
  ▼       ▼
Check 24h   Allow
passed?     Send
  │           │
┌─┴─┐         │
Yes No        │
│   │         │
▼   ▼         ▼
Reset  Return  Send Email
counter 429    │
│              ▼
└─────────►Increment
           counter
```

---

### Inbox Limit

**Rule**: Each user's inbox holds maximum **10 emails**. When the 11th arrives, the oldest is deleted.

**Implementation** (`domain/email/handler.go`):

```go
// After inserting new inbox email:
// 1. Count emails for user where email_type = 'inbox'
// 2. If count > 10:
//    - Find oldest email (ORDER BY timestamp ASC LIMIT 1)
//    - Delete attachments from S3
//    - Delete email record
```

---

### Login Rate Limiting

**Rule**: After **4 failed attempts**, account is locked for **5 minutes**.

**Implementation** (`domain/user/handler.go:28-209`):

```
Login Attempt
      │
      ▼
Check blocked_until > now?
      │
  ┌───┴───┐
  │ Yes   │ No
  ▼       ▼
Return   Verify
429      Credentials
         │
     ┌───┴───┐
     │ Wrong │ Correct
     ▼       ▼
Increment   Reset
counter     counter
     │       │
     ▼       │
Count >= 4?  │
  │          │
┌─┴─┐        │
Yes No       │
│   │        │
▼   ▼        ▼
Set  Return  Generate
block 401   JWT Token
5min
```

---

### Attachment Handling

**Rules**:
- Maximum **10 attachments** per email
- Maximum **10MB** per file
- Files expire after **7 days** (S3 lifecycle)
- Allowed types: `.pdf, .doc, .docx, .xls, .xlsx, .ppt, .pptx, .txt, .rtf, .odt, .ods, .odp, .jpg, .jpeg, .png, .gif, .bmp, .tiff, .mp3, .wav, .aac, .ogg, .mp4, .mov, .avi, .mkv, .zip, .rar, .7z, .tar, .gz, .webp`

**Upload Flow**:
```
1. User uploads file via POST /email/upload/attachment
2. Backend validates file type and size
3. Upload to S3: s3://bucket/attachments/{user_email}/{uuid}_{filename}
4. Return presigned URL (valid 3 days)
5. User includes URLs in send email request
```

---

### Password Security

**Implementation** (`utils/hashing.go`):

```go
// Hashing (bcrypt + salt)
saltedPassword := password + JWT_SECRET
hash := bcrypt.GenerateFromPassword(saltedPassword, bcrypt.DefaultCost)

// Verification
saltedAttempt := attempt + JWT_SECRET
bcrypt.CompareHashAndPassword(hash, saltedAttempt)
```

**Requirements**:
- Minimum 6 characters
- Letters and numbers allowed
- Can be admin-generated

---

## Third-Party Integrations

### AWS SES (Simple Email Service)

**File**: `pkg/aws.go`

**Functions**:

| Function | Description |
|----------|-------------|
| `InitAWS()` | Create AWS session with credentials |
| `SendEmail()` | Send raw MIME email via SES |
| `SendEmailWithAttachmentURL()` | Send with HTML attachment links |

**Configuration**:
```env
AWS_REGION=ap-southeast-2
AWS_ACCESS_KEY=your-access-key
AWS_SECRET_KEY=your-secret-key
```

**Email Format**:
- MIME multipart/mixed
- HTML body with base64 encoding
- Attachments as base64-encoded MIME parts

---

### AWS S3 (Storage)

**File**: `pkg/aws.go`

**Functions**:

| Function | Description |
|----------|-------------|
| `InitS3()` | Create S3 client |
| `UploadAttachment()` | Upload file, return public URL |
| `UploadPreSignAttachment()` | Upload file, return 3-day presigned URL |
| `DeleteS3ByMessageID()` | Delete single object |
| `DeleteS3FolderContents()` | Batch delete by prefix |
| `CreateBucketFolderEmailUser()` | Create user folder structure |

**Configuration**:
```env
S3_BUCKET_NAME=ses-user-received-inbox
S3_PREFIX=all@mailsaja.com/
```

**Bucket Structure**:
```
ses-user-received-inbox/
├── all@mailsaja.com/           # Incoming email prefix
│   └── {message-id}            # Raw .eml files
├── attachments/
│   └── {user-email}/
│       └── {uuid}_{filename}   # Uploaded attachments
└── {user-email}/               # User inbox folder
```

---

### Resend API

**File**: `pkg/resend.go`

**Function**:
```go
func SendEmailViaResend(from, to, subject, body string, attachments []Attachment) error {
    // 1. Select API key based on sender domain
    //    - @mailria.com → RESEND_MAILRIA_API
    //    - @mailsaja.com → RESEND_API
    // 2. Build SendEmailRequest with attachments as URLs
    // 3. Call client.Emails.Send()
}
```

**Configuration**:
```env
RESEND_API=re_xxxxx              # For @mailsaja.com
RESEND_MAILRIA_API=re_xxxxx      # For @mailria.com
```

**Features**:
- Supports URL-based attachments
- Automatic domain-based API key selection
- HTML email body support

---

### SMTP/Haraka

**File**: `pkg/smtp.go`

**Function**:
```go
func SendEmailWithHARAKA(toAddress, fromAddress, subject, htmlBody string, attachments []Attachment) error {
    // Uses gomail.v2 library
    // Supports inline attachments
    // HTML attachment formatting with Material Design icons
}
```

**Configuration**:
```env
SMTP_HOST=your-smtp-host
SMTP_PORT=587
SMTP_USERNAME=username
SMTP_PASSWORD=password
```

---

## Background Jobs

### Email Sync Job (`sync`)

**Entry Point**: `cmd/main.go:105-127`

**Schedule**: Every **10 seconds**

**Purpose**: Fetch incoming emails from S3 and store in database

**Flow**:
```
┌─────────────────────────────────────────────────────────────────┐
│                    SyncEmails() Function                         │
│                  domain/email/handler.go:1722                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │ List S3 objects with prefix   │
              │ (s3://bucket/all@mailsaja/)   │
              └───────────────┬───────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │   For each .eml file:         │
              │   1. Download from S3         │
              │   2. Parse headers (enmime)   │
              │   3. Extract recipient email  │
              └───────────────┬───────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │ Look up user in database      │
              │ SELECT id FROM users          │
              │ WHERE email = recipient       │
              └───────────────┬───────────────┘
                              │
              ┌───────────────┴───────────────┐
              │                               │
          User Found                    User Not Found
              │                               │
              ▼                               ▼
    ┌─────────────────┐             ┌─────────────────┐
    │ Insert into     │             │ Delete from S3  │
    │ incoming_emails │             │ (unregistered)  │
    │ table           │             └─────────────────┘
    └────────┬────────┘
             │
             ▼
    ┌─────────────────┐
    │ Delete from S3  │
    │ (processed)     │
    └─────────────────┘
```

**Code Reference**:
- Main function: `SyncEmails()` at `domain/email/handler.go:1722`
- Store logic: `storeRawEmail()` at `domain/email/handler.go:1802`
- Extract recipient: `extractRecipientEmail()` at `domain/email/handler.go:1876`

---

### Sent Email Cleanup Job (`sync_sent`)

**Entry Point**: `cmd/main.go:81-103`

**Schedule**: Every **24 hours**

**Purpose**: Delete sent emails older than 7 days and their S3 attachments

**Flow**:
```
┌─────────────────────────────────────────────────────────────────┐
│                 SyncSentEmails() Function                        │
│                domain/email/handler.go:1639                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │ SELECT * FROM emails          │
              │ WHERE email_type = 'sent'     │
              │ AND timestamp <= NOW() - 7d   │
              └───────────────┬───────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │   For each old email:         │
              │   1. Parse attachments JSON   │
              │   2. Extract S3 keys          │
              └───────────────┬───────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │ Delete each S3 attachment     │
              │ s3Client.DeleteObject()       │
              └───────────────┬───────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │ Delete email record           │
              │ DELETE FROM emails WHERE id=? │
              └───────────────────────────────┘
```

**Code Reference**: `SyncSentEmails()` at `domain/email/handler.go:1639-1718`

---

## Authentication & Authorization

### JWT Token Structure

**Generation** (`utils/jwt.go`):

```go
claims := jwt.MapClaims{
    "user_id": user.ID,
    "email":   user.Email,
    "role_id": user.RoleID,
    "exp":     time.Now().Add(720 * time.Hour).Unix(), // 30 days
}
token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
return token.SignedString([]byte(JWT_SECRET))
```

**Token Header Format**:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

---

### Middleware Chain

**File**: `middleware/auth.go`

```go
func JWTMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
    // 1. Extract "Authorization: Bearer <token>" header
    // 2. Validate token segments (must be 3 parts)
    // 3. Parse and validate with JWT_SECRET
    // 4. Check signing method is HMAC
    // 5. Extract claims and set in context:
    //    - c.Set("user_id", ...)
    //    - c.Set("email", ...)
    //    - c.Set("role_id", ...)
}
```

**File**: `middleware/role.go`

```go
func RoleMiddleware(allowedRoles []int) echo.MiddlewareFunc {
    // 1. Get role_id from context
    // 2. Check if role_id in allowedRoles
    // 3. Return 403 if not authorized
}
```

---

### Role-Based Access Control

| Role ID | Role Name | Permissions |
|---------|-----------|-------------|
| **0** | SuperAdmin | - Manage all users<br>- Manage admin accounts<br>- Manage domains<br>- View all inboxes<br>- All admin permissions |
| **1** | User | - View own inbox<br>- Send emails (3/day)<br>- Upload attachments<br>- Change own password |
| **2** | Admin | - Create/delete users<br>- View all user inboxes<br>- Bulk create users<br>- Cannot manage admins |

**Route Protection Examples**:
```go
superAdminOnly := []int{0}
admin := []int{0, 2}

// SuperAdmin only
userGroup.POST("/admin", handler, middleware.RoleMiddleware(superAdminOnly))

// Admin and SuperAdmin
userGroup.POST("/", handler, middleware.RoleMiddleware(admin))

// Any authenticated user
userGroup.GET("/get_user_me", handler) // Just JWT, no role check
```

---

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# ===================
# Database
# ===================
DATABASE_URL=root:password@tcp(127.0.0.1:3306)/mailria?parseTime=true

# ===================
# Security
# ===================
JWT_SECRET=your-super-secret-jwt-key-here

# ===================
# AWS Configuration
# ===================
AWS_REGION=ap-southeast-2
AWS_ACCESS_KEY=xxxx
AWS_SECRET_KEY=xx/xx/xx
S3_BUCKET_NAME=ses-user-received-inbox
S3_PREFIX=all@xx.com/
IAM_USERNAME=ses-user

# ===================
# SMTP (Haraka)
# ===================
SMTP_HOST=smtp.yourdomain.com
SMTP_PORT=587
SMTP_USERNAME=smtp-user
SMTP_PASSWORD=smtp-password

# ===================
# Support Emails
# ===================
EMAIL_SUPPORT=support@mailsaja.com
NAME_SUPPORT=Support Mailsaja
EMAIL_MAILRIA_SUPPORT=support@mailria.com
NAME_MAILRIA_SUPPORT=Support Mailria

# ===================
# Resend API
# ===================
RESEND_API=re_xxxxx_mailsaja_key
RESEND_MAILRIA_API=re_xxxxx_mailria_key
```

### Database Connection Pool

**File**: `config/config.go`

```go
DB.SetMaxOpenConns(10)           // Maximum concurrent connections
DB.SetMaxIdleConns(5)            // Maximum idle connections
DB.SetConnMaxLifetime(time.Hour) // Connection lifetime
```

---

## Deployment

### Production Setup with PM2

```bash
# 1. Build the binary
go build -o build/main cmd/main.go

# 2. Create PM2 ecosystem file
cat > ecosystem.config.js << 'EOF'
module.exports = {
  apps: [
    {
      name: 'go-server',
      script: './build/main',
      args: 'server',
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '1G',
    },
    {
      name: 'go-sync',
      script: './build/main',
      args: 'sync',
      instances: 1,
      autorestart: true,
      watch: false,
    },
    {
      name: 'go-sync-sent',
      script: './build/main',
      args: 'sync_sent',
      instances: 1,
      autorestart: true,
      watch: false,
    }
  ]
};
EOF

# 3. Start all services
pm2 start ecosystem.config.js

# 4. Save PM2 process list
pm2 save

# 5. Setup startup script
pm2 startup
```

### Nginx Reverse Proxy

```nginx
server {
    listen 80;
    server_name api.mailria.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

### Database Migrations

```bash
# Install goose
go install github.com/pressly/goose/v3/cmd/goose@latest

# Run all migrations
goose -dir migrations mysql "$DATABASE_URL" up

# Rollback last migration
goose -dir migrations mysql "$DATABASE_URL" down

# Check migration status
goose -dir migrations mysql "$DATABASE_URL" status
```

### GitHub Actions CI/CD

The project includes CI/CD in `.github/workflows/deploy.yml`:

```yaml
# Typical workflow:
# 1. Push to main branch
# 2. GitHub Actions builds the Go binary
# 3. SSH to EC2 server
# 4. Pull latest code
# 5. Rebuild and restart PM2 services
```

---

## Troubleshooting

### Common Issues

#### 1. "Failed to connect to database"
```bash
# Check MySQL is running
sudo systemctl status mysql

# Verify connection string
mysql -u root -p -h 127.0.0.1 -P 3306 mailria

# Check .env DATABASE_URL format
DATABASE_URL=user:password@tcp(host:port)/database?parseTime=true
```

#### 2. "Invalid or expired token"
```bash
# Token expired after 30 days - user needs to re-login
# Check JWT_SECRET matches between sessions
# Verify Authorization header format: "Bearer <token>"
```

#### 3. "Email limit exceeded"
```bash
# User sent 3 emails in 24 hours
# Wait 24 hours or admin can reset:
UPDATE users SET sent_emails = 0 WHERE email = 'user@mailria.com';
```

#### 4. "Failed to initialize AWS session"
```bash
# Check AWS credentials in .env
# Verify IAM user has SES and S3 permissions
# Test with AWS CLI:
aws ses get-account-sending-enabled
aws s3 ls s3://ses-user-received-inbox/
```

#### 5. Emails not syncing
```bash
# Check sync process is running
pm2 status go-sync

# Check S3 bucket has emails
aws s3 ls s3://ses-user-received-inbox/all@mailsaja.com/

# Check logs
pm2 logs go-sync --lines 100
```

#### 6. "Account temporarily locked"
```bash
# 4+ failed login attempts - wait 5 minutes
# Or manually unlock:
UPDATE user_login_attempts
SET failed_attempts = 0, blocked_until = NULL
WHERE username = 'user@mailria.com';
```

### Log Locations

| Service | Log Path |
|---------|----------|
| Go Server | `/home/ubuntu/.pm2/logs/go-server-out.log` |
| Go Sync | `/home/ubuntu/.pm2/logs/go-sync-out.log` |
| Go Sync Sent | `/home/ubuntu/.pm2/logs/go-sync-sent-out.log` |

### Health Check

```bash
# Check server is responding
curl http://localhost:8000/login -X POST -H "Content-Type: application/json" -d '{}'

# Expected: {"error":"..."} (not connection refused)
```

### Debug Mode

Add debug logging to handlers:
```go
fmt.Println("Debug:", variableName)
```

View logs:
```bash
pm2 logs go-server --lines 50
```

---

## QA Testing

Manual QA test cases are documented in:

- [QA-Test-Scenario.md](./QA-Test-Scenario.md)

---

## Dependencies

### Core Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `labstack/echo/v4` | v4.12.0 | HTTP framework |
| `jmoiron/sqlx` | v1.4.0 | SQL utilities |
| `go-sql-driver/mysql` | v1.8.1 | MySQL driver |
| `golang-jwt/jwt/v5` | v5.0.0 | JWT tokens |
| `spf13/viper` | v1.19.0 | Configuration |

### AWS & Email

| Library | Version | Purpose |
|---------|---------|---------|
| `aws/aws-sdk-go` | v1.55.5 | AWS SES & S3 |
| `resend/resend-go/v2` | v2.13.0 | Resend API |
| `jhillyerd/enmime` | v1.3.0 | MIME parsing |
| `gopkg.in/gomail.v2` | - | SMTP sending |

### Security

| Library | Version | Purpose |
|---------|---------|---------|
| `golang.org/x/crypto` | v0.29.0 | bcrypt hashing |
| `google/uuid` | v1.6.0 | UUID generation |

---

## Support

- **GitHub Issues**: [be-mail-platform/issues](https://github.com/Triaksa-Space/be-mail-platform/issues)
- **Frontend Repo**: [fe-mail-platform](https://github.com/Triaksa-Space/fe-mail-platform)

---

*Last updated: January 2025*


    What     │                         Details                         │
  ├──────────────┼─────────────────────────────────────────────────────────┤
  │ Domains      │ mailria.com                                             │
  ├──────────────┼─────────────────────────────────────────────────────────┤
  │ Admin users  │ superadmin@mailria.com / superadmin123 (role_id=2)      │
  ├──────────────┼─────────────────────────────────────────────────────────┤
  │              │ admin@mailria.com / admin123 (role_id=2)                │
  ├──────────────┼─────────────────────────────────────────────────────────┤
  │ Regular user │ user@mailria.com / user123 (role_id=1)                  │
  ├──────────────┼─────────────────────────────────────────────────────────┤
  │ Test users   │ person1@mailria.com … person5@mailria.com               │
  ├──────────────┼─────────────────────────────────────────────────────────┤
  │ Permissions  │ All 9 permissions auto-assigned to every role_id=2 user │
  ├──────────────┼─────────────────────────────────────────────────────────┤
  │ Emails       │ 25 inbox + 25 sent emails per user         