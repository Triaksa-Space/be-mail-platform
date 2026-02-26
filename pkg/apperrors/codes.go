package apperrors

// Error codes - organized by domain

// Authentication errors (AUTH_*)
const (
	ErrCodeInvalidCredentials  = "AUTH_INVALID_CREDENTIALS"
	ErrCodeTokenExpired        = "AUTH_TOKEN_EXPIRED"
	ErrCodeTokenInvalid        = "AUTH_TOKEN_INVALID"
	ErrCodeTokenMalformed      = "AUTH_TOKEN_MALFORMED"
	ErrCodeAccountLocked       = "AUTH_ACCOUNT_LOCKED"
	ErrCodeRefreshTokenInvalid = "AUTH_REFRESH_TOKEN_INVALID"
	ErrCodeRefreshTokenExpired = "AUTH_REFRESH_TOKEN_EXPIRED"
	ErrCodeRefreshTokenReused  = "AUTH_REFRESH_TOKEN_REUSED"
)

// Authorization errors (AUTHZ_*)
const (
	ErrCodeForbidden              = "AUTHZ_FORBIDDEN"
	ErrCodeInsufficientPermission = "AUTHZ_INSUFFICIENT_PERMISSION"
	ErrCodeInvalidRole            = "AUTHZ_INVALID_ROLE"
)

// Validation errors (VALIDATION_*)
const (
	ErrCodeValidationFailed  = "VALIDATION_FAILED"
	ErrCodeInvalidEmail      = "VALIDATION_INVALID_EMAIL"
	ErrCodeInvalidPassword   = "VALIDATION_INVALID_PASSWORD"
	ErrCodeInvalidInput      = "VALIDATION_INVALID_INPUT"
	ErrCodeMissingField      = "VALIDATION_MISSING_FIELD"
	ErrCodeInvalidFormat     = "VALIDATION_INVALID_FORMAT"
)

// Resource errors (RESOURCE_*)
const (
	ErrCodeUserNotFound    = "RESOURCE_USER_NOT_FOUND"
	ErrCodeEmailNotFound   = "RESOURCE_EMAIL_NOT_FOUND"
	ErrCodeDomainNotFound  = "RESOURCE_DOMAIN_NOT_FOUND"
	ErrCodeFileNotFound    = "RESOURCE_FILE_NOT_FOUND"
	ErrCodeResourceExists  = "RESOURCE_ALREADY_EXISTS"
)

// Rate limiting errors (RATE_*)
const (
	ErrCodeRateLimitExceeded  = "RATE_LIMIT_EXCEEDED"
	ErrCodeEmailLimitExceeded = "RATE_EMAIL_LIMIT_EXCEEDED"
	ErrCodeLoginLimitExceeded = "RATE_LOGIN_LIMIT_EXCEEDED"
)

// Internal errors (INTERNAL_*)
const (
	ErrCodeDatabaseError    = "INTERNAL_DATABASE_ERROR"
	ErrCodeEmailSendFailed  = "INTERNAL_EMAIL_SEND_FAILED"
	ErrCodeS3Error          = "INTERNAL_S3_ERROR"
	ErrCodeAWSError         = "INTERNAL_AWS_ERROR"
	ErrCodeParseError       = "INTERNAL_PARSE_ERROR"
	ErrCodeUnexpectedError  = "INTERNAL_UNEXPECTED_ERROR"
)

// Email specific errors (EMAIL_*)
const (
	ErrCodeEmailParseFailed   = "EMAIL_PARSE_FAILED"
	ErrCodeEmailUploadFailed  = "EMAIL_UPLOAD_FAILED"
	ErrCodeEmailProcessFailed = "EMAIL_PROCESS_FAILED"
	ErrCodeAttachmentFailed   = "EMAIL_ATTACHMENT_FAILED"
)
