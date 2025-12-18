export const Messages = {
  // ───── General ─────
  SUCCESS: 'Operation completed successfully',
  FAILED: 'Something went wrong. Please try again.',
  SERVER_ERROR: 'Internal server error. Our team has been notified.',
  BAD_REQUEST: 'The request could not be processed due to invalid data',
  VALIDATION_FAILED: 'Validation failed. Please check your inputs.',
  NOT_FOUND: 'The requested resource could not be found',
  ROUTE_NOT_FOUND: 'Endpoint not found',
  UNAUTHORIZED: 'Please log in to access this resource', // More user-friendly than "Authentication required"
  FORBIDDEN: 'You do not have permission to access this resource',
  TOO_MANY_REQUESTS: 'Too many requests. Please try again later.',
  UNDER_MAINTENANCE:
    'System is currently under maintenance. Please try again later.',
  FEATURE_UNAVAILABLE: 'This feature is currently unavailable',

  // ───── Auth ─────
  LOGIN_SUCCESS: 'Logged in successfully',
  LOGIN_FAILED: 'Invalid email or password', // Generic message prevents account enumeration hacking
  LOGOUT_SUCCESS: 'Logged out successfully',
  TOKEN_INVALID: 'Invalid authentication token',
  TOKEN_EXPIRED: 'Your session has expired. Please log in again.', // Clear instruction for the user
  TOKEN_REQUIRED: 'Authentication token is missing',
  TOKEN_REFRESHED: 'Session refreshed successfully',
  ACCESS_DENIED: 'Access denied. Administrator privileges required.',

  // ───── Verification ─────
  EMAIL_VERIFIED: 'Email verified successfully! You can now log in.',
  EMAIL_NOT_VERIFIED: 'Please verify your email address to continue.',
  EMAIL_ALREADY_VERIFIED: 'Your email is already verified.',
  VERIFICATION_EMAIL_SENT: 'A verification link has been sent to your email.',
  VERIFICATION_TOKEN_INVALID: 'Invalid or expired verification link.',
  VERIFICATION_TOKEN_EXPIRED:
    'Verification link has expired. Please request a new one.',
  MISSING_VERIFICATION_TOKEN: 'Verification token is missing.',
  MISSING_RESET_PASSWORD_TOKEN: 'Reset token is missing.',

  // ───── User Profile ─────
  USER_NOT_FOUND: 'User not found', // ⚠️ NOTE: Use carefully. Don't return this in public login/forgot-password APIs.
  USER_CREATED: 'Account created successfully',
  USER_UPDATED: 'Profile updated successfully',
  USER_DELETED: 'Account deleted successfully',
  USER_ALREADY_EXISTS: 'An account with this email already exists',
  NO_VALID_FIELD: 'No valid fields provided for update',
  PROFILE_FETCHED: 'Profile retrieved successfully',
  PASSWORD_CHANGED: 'Password updated successfully',

  // ───── Password Reset ─────
  PASSWORD_RESET_REQUESTED:
    'If an account exists with this email, a reset link has been sent.', // Perfect for security
  PASSWORD_RESET_SUCCESS:
    'Your password has been reset successfully. You can now log in.',
  PASSWORD_RESET_FAILED: 'Failed to reset password. Link may be expired.',
  PASSWORD_WEAK: 'Password is too weak. Please use a stronger password.',
  SAME_PASSWORD: 'New password must be different from your current password.', // Much clearer
  INVALID_OLD_PASSWORD: 'The current password provided is incorrect.',

  // ───── Security / Abuse ─────
  ACCOUNT_LOCKED:
    'Account temporarily locked due to multiple failed login attempts.',
  SUSPICIOUS_ACTIVITY:
    'Unusual activity detected. Please verify your identity.',

  // ───── Email / Notifications ─────
  EMAIL_SENT: 'Email sent successfully',
  EMAIL_FAILED: 'Failed to send email. Please try again later.',

  // ───── Database ─────
  DB_CONNECTION_ERROR: 'Service unavailable. Could not connect to database.',
  DB_OPERATION_FAILED: 'The operation failed due to a database error.',

  // ───── File Uploads ─────
  FILE_UPLOAD_SUCCESS: 'File uploaded successfully',
  FILE_UPLOAD_FAILED: 'File upload failed. Please try again.',
  FILE_TOO_LARGE: 'File size exceeds the maximum allowed limit',
  FILE_TYPE_NOT_ALLOWED: 'This file type is not supported',

  // ───── Admin ─────
  ADMIN_CREATED: 'Admin account created successfully',
  ADMIN_UPDATED: 'Admin details updated successfully',
  ADMIN_DELETED: 'Admin account deleted successfully',
  ADMIN_NOT_FOUND: 'Admin account not found',
  ADMIN_ACTION_FORBIDDEN: 'This action is restricted to administrators only',

  // ───── System / Misc ─────
  INVALID_REQUEST: 'Invalid request format',
  CONFIG_ERROR: 'Server configuration error',
  HEALTH_OK: 'System is operational'
}

// Machine-friendly codes (Perfect as-is)
export const MessageCodes = {
  VALIDATION_FAILED: 'VALIDATION_FAILED',
  UNAUTHORIZED: 'UNAUTHORIZED',
  FORBIDDEN: 'FORBIDDEN',
  NOT_FOUND: 'NOT_FOUND',
  USER_EXISTS: 'USER_EXISTS',
  EMAIL_NOT_VERIFIED: 'EMAIL_NOT_VERIFIED',
  VERIFICATION_EXPIRED: 'VERIFICATION_EXPIRED',
  PASSWORD_WEAK: 'PASSWORD_WEAK',
  ACCOUNT_LOCKED: 'ACCOUNT_LOCKED',
  RATE_LIMITED: 'RATE_LIMITED',
  TOKEN_INVALID: 'TOKEN_INVALID',
  SERVER_ERROR: 'SERVER_ERROR'
}
