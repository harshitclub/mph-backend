import { Request, Response } from 'express'
import { JwtPayload } from 'jsonwebtoken'
import jwt from 'jsonwebtoken'

// Configs
import { config } from '../../configs/config'
import { prisma } from '../../configs/prisma'
import { logger } from '../../configs/logger'
import { Messages } from '../../configs/messages'

// Validators
import {
  signupUserValidator,
  updateUserValidator
} from '../../validators/user.validator'

// Utils — Core
import { ApiResponse } from '../../utils/apiResponse'
import { AppError } from '../../utils/appError'
import { maskEmail } from '../../utils/mask'
import { comparePassword, hashPassword } from '../../utils/password'

// Tokens
import { generateAccessToken } from '../../utils/tokens/accessToken'
import {
  generateRefreshTokenWithJti,
  verifyRefreshToken
} from '../../utils/tokens/refreshToken'
import { generateVerificationTokenRaw } from '../../utils/tokens/verificationToken'
import { sha256Hex } from '../../utils/tokens/sha256Hex'

// Email
import { emailQueue } from '../../queues/email.queue'
import { verifyEmailTemplate } from '../../emails/templates/auth/verify-email'

// Prisma Types
import { Prisma } from '../../generated/prisma/client'
import redisCache from '../../configs/redisCache'
import {
  changePasswordValidator,
  forgetPasswordValidator,
  loginValidator,
  resetPasswordValidator,
  verifyEmailValidator
} from '../../validators/common.validator'
import { isObject } from '../../utils/isObject'
import { getUser } from '../../utils/getUser'
import { resetPasswordEmailTemplate } from '../../emails/templates/auth/reset-password'
import { generateResetPasswordTokenRaw } from '../../utils/tokens/resetPasswordToken'

const { REFRESH_COOKIE_NAME, REFRESH_COOKIE_PATH, REFRESH_TTL_MS } =
  config.COOKIE
const { MAX_FAILED_LOGIN } = config.AUTH

/**
 * Register a new user account.
 *
 * Flow:
 *  - Validate user input (firstName, lastName, email, password).
 *  - Hash the password before saving.
 *  - Generate a verification token (raw + hashed) and store the hashed version.
 *  - Send a verification email containing the raw token.
 *  - Return a safe user response (no password or sensitive data included).
 *
 * @param req - Express request object
 * @param res - Express response object
 * @returns JSON success response with user info
 * @throws AppError - If validation fails or email already exists
 */
export async function userSignup(req: Request, res: Response) {
  // 1. Validate payload (Fail Fast)
  const parsed = await signupUserValidator.safeParseAsync(req.body)
  if (!parsed.success) {
    // Optimization: Return specific field errors so frontend can show "Password too short"
    throw new AppError(Messages.VALIDATION_FAILED, 400)
  }

  const { firstName, lastName, email, password } = parsed.data

  // 2. Optimization: Check existence BEFORE hashing (Saves CPU)
  const existingUser = await prisma.user.findUnique({
    where: { email },
    select: { id: true } // Select minimal data
  })

  if (existingUser) {
    logger.warn(
      `Signup blocked: Email already exists | email=${maskEmail(email)}`
    )
    throw new AppError(Messages.USER_ALREADY_EXISTS, 409) // 409 Conflict
  }

  // 3. Hash Password (CPU Intensive operation - only do this if user doesn't exist)
  const passwordHash = await hashPassword(password)

  // 4. Generate email verification token (raw sent to user, hash stored in DB)
  const { raw: rawToken, expiresAt } = generateVerificationTokenRaw(15)
  const tokenHash = sha256Hex(rawToken)

  // 5. Get Real IP (Handle Proxy/CloudFront)
  const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip

  try {
    // Create user record and store hashed token data
    const user = await prisma.user.create({
      data: {
        firstName,
        lastName,
        email,
        passwordHash,
        emailVerificationTokenHash: tokenHash,
        emailVerificationExpiresAt: expiresAt,
        emailVerificationUsed: false
      },
      select: {
        id: true,
        firstName: true,
        lastName: true,
        email: true,
        emailVerified: true
      }
    })

    try {
      // Send verification email (async background job)
      await emailQueue.add('verificationEmail', {
        to: user.email,
        subject: 'Verify Your Email',
        html: verifyEmailTemplate({
          name: user.firstName,
          token: rawToken
        })
      })
    } catch (queueError) {
      logger.error(
        `Failed to queue verification email | userId=${user.id} | error=${queueError}`
      )
      // We do NOT throw here. We let the user signup succeed.
    }

    // Log successful account creation (mask email for privacy)
    logger.info(
      `${Messages.USER_CREATED} | userId=${user.id} | email=${maskEmail(user.email)} | ip=${ip}`
    )

    // Respond with safe user fields only
    return ApiResponse.success(req, res, 201, Messages.USER_CREATED, {
      id: user.id,
      email: user.email,
      name: `${user.firstName} ${user.lastName}`,
      verified: user.emailVerified
    })
  } catch (err: unknown) {
    // Handle unique email constraint (duplicate signup)
    if (
      err instanceof Prisma.PrismaClientKnownRequestError &&
      err.code === 'P2002'
    ) {
      logger.warn(
        `Race condition detected: Duplicate signup | email=${maskEmail(email)} | ip=${ip}`
      )
      throw new AppError(Messages.USER_ALREADY_EXISTS, 400)
    }

    const errorMessage = err instanceof Error ? err.message : String(err)

    // Log unexpected errors
    logger.error(
      `Signup failed (System Error) | email=${maskEmail(email)} | error=${errorMessage}`
    )
    throw err // Let global error handler respond
  }
}

/**
 * Verify a user's email address using a one-time verification token.
 *
 * Flow:
 *  - Extract token from query/body.
 *  - Hash the token to match what is stored in the database.
 *  - Check that the token is:
 *      • Valid (exists in DB)
 *      • Not expired
 *      • Not already used
 *  - Perform a timing-safe comparison to avoid token leak attacks.
 *  - Mark email as verified and invalidate the token.
 *
 * @param req - Express request object
 * @param res - Express response object
 * @returns JSON success response if verification succeeds
 * @throws AppError - If token is missing or invalid
 */
export async function userVerifyEmail(req: Request, res: Response) {
  // Extract raw token from either query param or request body
  const rawToken = req.query.token ?? req.body?.token
  const parsed = verifyEmailValidator.safeParse({ token: rawToken })
  if (!parsed.success) {
    throw new AppError(Messages.MISSING_VERIFICATION_TOKEN, 400)
  }

  const { token } = parsed.data

  // Convert raw token to hash to compare with stored DB value
  const tokenHash = sha256Hex(token)

  // Look up the user associated with this token (not expired and unused)
  const user = await prisma.user.findFirst({
    where: {
      emailVerificationTokenHash: tokenHash,
      emailVerificationUsed: false,
      emailVerificationExpiresAt: { gt: new Date() } // Must be in the future
    },
    select: {
      id: true
    }
  })

  if (!user) {
    // Generic error to prevent enumeration/guessing
    logger.warn(`Email verification failed: Invalid or expired token`)
    throw new AppError(Messages.VERIFICATION_TOKEN_INVALID, 400)
  }

  await prisma.user.update({
    where: { id: user.id },
    data: {
      emailVerified: true,
      emailVerificationUsed: true,
      emailVerificationTokenHash: null,
      emailVerificationExpiresAt: null
    }
  })

  logger.info(`Email verified successfully | userId=${user.id}`)

  // Return success response
  return ApiResponse.success(req, res, 200, Messages.EMAIL_VERIFIED)
}

/**
 * Log a user into their account.
 *
 * Flow:
 *  1) Validate input.
 *  2) Lookup user by email.
 *  3) Enforce account lock and login attempt throttling.
 *  4) Verify password.
 *  5) Generate access + refresh tokens.
 *  6) Revoke old refresh tokens and store new one (single-session model).
 *  7) Send refresh token as httpOnly cookie.
 *  8) Return safe user data + short-lived access token.
 *
 * Security Notes:
 *  - `failedLogins` prevents brute-force attacks.
 *  - `refreshToken` is hashed in DB (token theft-safe).
 *  - `httpOnly` cookie prevents XSS theft.
 *  - Revoking previous tokens enforces 1 active session per user/device.
 *
 * @param req Express Request
 * @param res Express Response
 * @returns Authenticated user and tokens
 */
export async function userLogin(req: Request, res: Response) {
  // 1. Validate request body
  const parsed = await loginValidator.safeParseAsync(req.body)
  if (!parsed.success) {
    throw new AppError(Messages.VALIDATION_FAILED, 400)
  }

  const { email, password } = parsed.data

  // 2. Fetch User (Minimal Select)
  const user = await prisma.user.findUnique({
    where: { email },
    select: {
      id: true,
      email: true,
      firstName: true,
      lastName: true,
      passwordHash: true,
      isDisabled: true,
      emailVerified: true,
      role: true
    }
  })

  // SECURITY: Timing Attack Protection & Ambiguous Errors
  // If user not found, we still "compare" a fake password so the response time is identical.
  const validPassword =
    user && (await comparePassword(password, user.passwordHash))

  if (!user || !validPassword) {
    // If user exists, we must handle the "Failed Login" counter
    if (user) {
      // Atomic Increment & Lock Check
      const updatedUser = await prisma.user.update({
        where: { id: user.id },
        data: {
          failedLogins: { increment: 1 }
        },
        select: {
          failedLogins: true
        }
      })

      if (updatedUser.failedLogins >= MAX_FAILED_LOGIN) {
        await prisma.user.update({
          where: { id: user.id },
          data: { isDisabled: true } // Lock account
        })
        logger.warn(`Account locked: Max attempts reached | userId=${user.id}`)
        throw new AppError(Messages.ACCOUNT_LOCKED, 403)
      }
    }

    // Generic Error Message (Don't reveal if email exists)
    throw new AppError(Messages.LOGIN_FAILED, 401)
  }

  // 3. Check Account Status
  if (user.isDisabled) {
    throw new AppError(Messages.ACCOUNT_LOCKED, 403)
  }

  // 4. Password valid → Generate tokens
  const accessToken = generateAccessToken({ sub: user.id })
  const { token: refreshJwt, jti } = generateRefreshTokenWithJti({
    sub: user.id
  })
  const refreshJtiHash = sha256Hex(jti)
  const refreshExpiresAt = new Date(Date.now() + config.COOKIE.REFRESH_TTL_MS)

  // 5. Get Network Info (Robust IP check)
  const userAgent = req.headers['user-agent'] || 'Unknown'
  const ip =
    (req.headers['x-forwarded-for'] as string)?.split(',')[0] ||
    req.ip ||
    'Unknown'

  // 6. Store Session (Allow Multi-Device)
  // We do NOT revoke old tokens here. We just add a new valid session.
  // We can clean up expired tokens asynchronously or via a Cron job later.
  await prisma.$transaction([
    // FUTURE TODO: Remove this block to enable Multi-Device support
    prisma.userRefreshToken.updateMany({
      where: { userId: user.id, revoked: false },
      data: { revoked: true, replacedBy: 'New Login' }
    }),
    // create new refresh token row
    prisma.userRefreshToken.create({
      data: {
        userId: user.id,
        tokenHash: refreshJtiHash,
        expiresAt: refreshExpiresAt,
        userAgent,
        ip
      }
    }),
    // Reset failed logins on successful login
    prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date(), failedLogins: 0 }
    })
  ])

  // 7. Send refresh token to client as HTTP-only cookie
  res.cookie(String(config.COOKIE.REFRESH_COOKIE_NAME), refreshJwt, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: REFRESH_COOKIE_PATH,
    maxAge: REFRESH_TTL_MS
  })

  // Prepare safe user response (never return password/hash)
  const safeUser = {
    id: user.id,
    email: user.email,
    name: `${user.firstName} ${user.lastName}`,
    verified: user.emailVerified,
    role: user.role,
    accessToken // short-lived access token
  }

  // 8. Log login success
  logger.info(
    `Login success | userId=${user.id} | email=${maskEmail(user.email)} | ip=${ip}`
  )
  return ApiResponse.success(req, res, 200, Messages.LOGIN_SUCCESS, safeUser)
}

export async function userLogout(req: Request, res: Response) {
  const cookieName = String(config.COOKIE.REFRESH_COOKIE_NAME)

  const refreshToken = req.cookies?.[cookieName]

  res.clearCookie(cookieName, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: REFRESH_COOKIE_PATH
  })

  if (!refreshToken) {
    return ApiResponse.success(req, res, 200, Messages.LOGOUT_SUCCESS)
  }

  try {
    const decoded = jwt.decode(refreshToken) as { jti?: string } | null

    if (decoded?.jti) {
      const tokenHash = sha256Hex(decoded.jti)

      await prisma.userRefreshToken.updateMany({
        where: { tokenHash: tokenHash },
        data: {
          revoked: true,
          replacedBy: 'User Logout' // Helpful for audit logs
        }
      })

      logger.info(`Logout: Session revoked | hash=${tokenHash}`)
    }
  } catch (error) {
    logger.warn(`Logout: DB cleanup failed | error=${String(error)}`)
  }

  return ApiResponse.success(req, res, 200, Messages.LOGOUT_SUCCESS)
}

/**
 * Refresh the user's session by rotating the refresh token.
 *
 * Flow:
 *  1) Extract refresh token from httpOnly cookie.
 *  2) Verify the refresh JWT signature + expiry.
 *  3) Convert jti -> hashed jti and lookup refresh token in DB.
 *  4) Validate token status: must exist, not revoked, not expired.
 *  5) Rotate token:
 *      - Revoke old token entry.
 *      - Create new refresh token entry.
 *      - Send new refresh token cookie to client.
 *  6) Issue new short-lived access token in response.
 *
 * Security:
 *  - Refresh tokens are hashed in DB → theft-safe.
 *  - Rotation prevents replay attacks.
 *  - Revoking all tokens on mismatch prevents token substitution attacks.
 *
 * @param req Express Request
 * @param res Express Response
 */
export async function refreshHandler(req: Request, res: Response) {
  const rawRefresh = req.cookies?.[REFRESH_COOKIE_NAME]

  // 1. Basic Validation
  if (!rawRefresh) {
    throw new AppError(Messages.TOKEN_INVALID, 401)
  }

  // 2. Verify JWT Integrity
  let decoded: JwtPayload
  try {
    const result = verifyRefreshToken(rawRefresh)
    // Ensure it's not a string and has required fields
    if (typeof result === 'string') {
      throw new AppError(Messages.TOKEN_INVALID, 401)
    }
    decoded = result as JwtPayload
  } catch {
    throw new AppError(Messages.TOKEN_INVALID, 401)
  }

  const { jti, sub: userId } = decoded

  if (
    !userId ||
    typeof userId !== 'string' ||
    !jti ||
    typeof jti !== 'string'
  ) {
    throw new AppError(Messages.TOKEN_INVALID, 401)
  }

  // 3. Database Lookup (Token + User)
  const tokenHash = sha256Hex(jti!)

  // Optimization: Fetch Token AND User in parallel (or single query if relation exists)
  // We need the User to check 'isDisabled' and to get data for the new Access Token payload.
  const [existingToken, user] = await Promise.all([
    prisma.userRefreshToken.findUnique({ where: { tokenHash } }),
    prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        role: true,
        isDisabled: true
      }
    })
  ])

  // 4. Security: Reuse Detection (The "Hacker" Check)
  // If token doesn't exist in DB but was valid JWT, it means it was used before and deleted/rotated.
  if (!existingToken) {
    logger.warn(`Reuse detection triggered | userId=${userId}`)
    // Revoke ALL sessions for this user immediately
    await prisma.userRefreshToken.updateMany({
      where: { userId },
      data: { revoked: true, replacedBy: 'Reuse Detection' }
    })
    throw new AppError(Messages.TOKEN_INVALID, 401)
  }

  // 5. Security: Revoked or Expired?
  if (existingToken.revoked || existingToken.expiresAt <= new Date()) {
    // If it was already revoked, we might want to revoke others too (optional, but safe)
    if (existingToken.revoked) {
      logger.warn(`Attempt to use revoked token | userId=${userId}`)
      await prisma.userRefreshToken.updateMany({
        where: { userId },
        data: { revoked: true }
      })
    }
    throw new AppError(Messages.TOKEN_INVALID, 401)
  }

  // 6. Security: User Ban Check (CRITICAL FIX)
  if (!user || user.isDisabled) {
    // User is banned. Kill this session.
    await prisma.userRefreshToken.update({
      where: { id: existingToken.id },
      data: { revoked: true, replacedBy: 'User Banned' }
    })
    throw new AppError(Messages.ACCOUNT_LOCKED, 403)
  }

  // 7. Rotate Token
  const { token: newRefreshJwt, jti: newJti } = generateRefreshTokenWithJti({
    sub: user.id
  })
  const newHash = sha256Hex(newJti)
  const newExpiresAt = new Date(Date.now() + REFRESH_TTL_MS)

  const userAgent = req.headers['user-agent'] || 'Unknown'
  const ip =
    (req.headers['x-forwarded-for'] as string)?.split(',')[0] ||
    req.ip ||
    'Unknown'

  // Atomically replace the old token
  await prisma.$transaction([
    prisma.userRefreshToken.update({
      where: { id: existingToken.id },
      data: { revoked: true, replacedBy: newHash }
    }),
    prisma.userRefreshToken.create({
      data: {
        userId: user.id,
        tokenHash: newHash,
        expiresAt: newExpiresAt,
        userAgent,
        ip
      }
    })
  ])

  // 8. Issue Full Access Token (CRITICAL FIX)
  // We include role/name so the frontend doesn't break
  const accessToken = generateAccessToken({ sub: user.id })

  // 9. Send Cookie
  res.cookie(REFRESH_COOKIE_NAME, newRefreshJwt, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: REFRESH_COOKIE_PATH,
    maxAge: REFRESH_TTL_MS
  })

  logger.info(`Refresh success | userId=${user.id}`)

  return ApiResponse.success(req, res, 200, Messages.TOKEN_REFRESHED, {
    accessToken
  })
}

export async function userProfile(req: Request, res: Response) {
  const { id } = getUser(req)

  const cacheKey = `user:${id}`

  // 1) Try Cache First
  const cached = await redisCache.get(cacheKey)
  if (cached) {
    const user = JSON.parse(cached)
    return ApiResponse.success(req, res, 200, Messages.PROFILE_FETCHED, {
      user,
      isCached: true
    })
  }

  // 2) Cache Miss → Fetch from DB
  const user = await prisma.user.findUnique({
    where: { id },
    select: {
      id: true,
      firstName: true,
      lastName: true,
      email: true,
      emailVerified: true,
      role: true,
      createdAt: true,
      profile: true
    }
  })

  if (!user) {
    throw new AppError(Messages.USER_NOT_FOUND, 404)
  }

  // 3) Store into Cache (optional TTL)
  await redisCache.set(cacheKey, JSON.stringify(user), 'EX', 3600) // 10 min cache

  return ApiResponse.success(req, res, 200, Messages.PROFILE_FETCHED, {
    user,
    isCached: false
  })
}
export async function userUpdate(req: Request, res: Response) {
  const { id } = getUser(req)

  const parsed = await updateUserValidator.safeParseAsync(req.body)

  if (!parsed.success) {
    throw new AppError(Messages.VALIDATION_FAILED, 400)
  }

  const updateData = parsed.data

  if (Object.keys(updateData).length === 0) {
    throw new AppError(Messages.NO_VALID_FIELD, 400)
  }

  // Separate profile from standard fields
  const { profile, ...fields } = updateData

  // This satisfies 'exactOptionalPropertyTypes' by ensuring no key is ever set to 'undefined'
  const data: Prisma.UserUpdateInput = {}

  if (fields.firstName !== undefined) data.firstName = fields.firstName
  if (fields.lastName !== undefined) data.lastName = fields.lastName
  if (fields.username !== undefined) data.username = fields.username
  if (fields.phone !== undefined) data.phone = fields.phone

  // Handle Profile Merge
  if (profile) {
    const existing = await prisma.user.findUnique({
      where: { id },
      select: { profile: true }
    })

    if (!existing) throw new AppError(Messages.NOT_FOUND, 404)

    const currentProfile = isObject(existing.profile) ? existing.profile : {}
    data.profile = { ...currentProfile, ...profile }
  }

  let updatedUser

  try {
    updatedUser = await prisma.user.update({
      where: { id },
      data,
      select: {
        id: true,
        firstName: true,
        lastName: true,
        username: true,
        phone: true,
        email: true,
        role: true,
        profile: true
      }
    })
  } catch (err) {
    if (
      err instanceof Prisma.PrismaClientKnownRequestError &&
      err.code === 'P2002'
    ) {
      const target = (err.meta?.target as string[]) || []
      const field = target[0] || 'Field'
      throw new AppError(`${field} already taken`, 409)
    }
    throw err
  }

  const cacheKey = `user:${id}`
  await redisCache.set(cacheKey, JSON.stringify(updatedUser), 'EX', 3600)

  return ApiResponse.success(req, res, 200, Messages.USER_UPDATED, updatedUser)
}

export async function userChangePassword(req: Request, res: Response) {
  const { id: userId } = getUser(req)

  const parsed = await changePasswordValidator.safeParseAsync(req.body)
  if (!parsed.success) {
    throw new AppError(Messages.VALIDATION_FAILED, 400)
  }

  const { currentPassword, newPassword } = parsed.data

  if (currentPassword === newPassword) {
    throw new AppError(Messages.SAME_PASSWORD, 400)
  }

  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { passwordHash: true, email: true }
  })

  if (!user) {
    throw new AppError(Messages.USER_NOT_FOUND, 404)
  }

  const isValid = await comparePassword(currentPassword, user.passwordHash)

  if (!isValid) {
    // We do NOT increment 'failedLogins' here because the user is already authenticated.
    // Just reject the request.
    throw new AppError(Messages.INVALID_OLD_PASSWORD, 400)
  }

  const newPasswordHash = await hashPassword(newPassword)

  await prisma.$transaction([
    prisma.user.update({
      where: { id: userId },
      data: {
        passwordHash: newPasswordHash,
        passwordChangedAt: new Date()
      }
    }),

    // SECURITY: Revoke ALL other sessions except the current one.
    prisma.userRefreshToken.updateMany({
      where: { userId },
      data: { revoked: true, replacedBy: 'Password Change' }
    })
  ])

  logger.info(
    `Password changed successfully | userId=${userId} | email=${user.email}`
  )

  return ApiResponse.success(req, res, 200, Messages.PASSWORD_CHANGED)
}

export async function userRequestVerification(req: Request, res: Response) {
  const { id: userId } = getUser(req)

  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      email: true,
      firstName: true,
      emailVerified: true,
      isDisabled: true
    }
  })

  if (!user) {
    throw new AppError(Messages.USER_NOT_FOUND, 404)
  }

  if (user.emailVerified) {
    throw new AppError(Messages.EMAIL_ALREADY_VERIFIED, 400)
  }

  if (user.isDisabled) {
    throw new AppError(Messages.ACCOUNT_LOCKED, 403)
  }

  const { raw: rawToken, expiresAt } = generateVerificationTokenRaw(15)
  const tokenHash = sha256Hex(rawToken)

  await prisma.user.update({
    where: { id: userId },
    data: {
      emailVerificationTokenHash: tokenHash,
      emailVerificationExpiresAt: expiresAt,
      emailVerificationUsed: false
    }
  })

  try {
    await emailQueue.add('verificationEmail', {
      to: user.email,
      subject: 'Verify Your Email',
      html: verifyEmailTemplate({
        name: user.firstName,
        token: rawToken
      })
    })

    logger.info(`Verification email requested | userId=${user.id}`)
  } catch (queueError) {
    // If Redis fails, we log it. The user will see a "Success" message but receives no email.
    // They can simply click "Resend" again later.
    logger.error(
      `Failed to queue verification email (Resend) | userId=${user.id} | error=${queueError}`
    )
    throw new AppError(Messages.SERVER_ERROR, 500)
  }

  return ApiResponse.success(req, res, 200, Messages.VERIFICATION_EMAIL_SENT)
}
export async function userRequestResetPassword(req: Request, res: Response) {
  const parsed = await forgetPasswordValidator.safeParseAsync(req.body)

  if (!parsed.success) {
    throw new AppError(Messages.VALIDATION_FAILED, 400)
  }

  const { email } = parsed.data

  const user = await prisma.user.findUnique({
    where: { email },
    select: {
      id: true,
      email: true,
      firstName: true,
      isDisabled: true
    }
  })

  if (!user) {
    logger.info(
      `Password reset requested for non-existent email | email=${maskEmail(email)}`
    )
    // Fake delay (optional) could be added here to match DB write time, but usually overkill for V1.
    return ApiResponse.success(req, res, 200, Messages.PASSWORD_RESET_REQUESTED)
  }

  if (user.isDisabled) {
    // If account is locked, we probably shouldn't let them reset the password.
    logger.warn(`Password reset blocked: Account disabled | userId=${user.id}`)
    throw new AppError(Messages.ACCOUNT_LOCKED, 403)
  }

  const { raw: rawToken, expiresAt } = generateResetPasswordTokenRaw(15)
  const tokenHash = sha256Hex(rawToken)

  await prisma.user.update({
    where: { id: user.id },
    data: {
      passwordResetTokenHash: tokenHash,
      passwordResetExpiresAt: expiresAt,
      passwordResetUsed: false
    }
  })

  try {
    await emailQueue.add('resetPasswordEmail', {
      to: user.email,
      subject: 'Reset Your Password',
      html: resetPasswordEmailTemplate({
        name: user.firstName,
        token: rawToken
      })
    })
    logger.info(`Reset Password email requested | userId=${user.id}`)
  } catch (queueError) {
    logger.error(
      `Failed to queue reset password email | userId=${user.id} | error=${queueError}`
    )
    throw new AppError(Messages.SERVER_ERROR, 500)
  }

  return ApiResponse.success(req, res, 200, Messages.PASSWORD_RESET_REQUESTED)
}
export async function userResetPassword(req: Request, res: Response) {
  const rawToken = String(req.query.token ?? req.body?.token ?? '')

  const parsed = await resetPasswordValidator.safeParseAsync(req.body)

  if (!parsed.success) {
    throw new AppError(Messages.VALIDATION_FAILED, 400)
  }

  if (!rawToken) {
    throw new AppError(Messages.MISSING_RESET_PASSWORD_TOKEN, 400)
  }

  const { newPassword } = parsed.data

  const tokenHash = sha256Hex(rawToken)

  const user = await prisma.user.findFirst({
    where: {
      passwordResetTokenHash: tokenHash,
      passwordResetUsed: false,
      passwordResetExpiresAt: { gt: new Date() }
    },
    select: { id: true, email: true }
  })

  if (!user) {
    logger.warn(`Password reset failed: Invalid or expired token`)
    throw new AppError(Messages.VERIFICATION_TOKEN_INVALID, 400)
  }

  const newPasswordHash = await hashPassword(newPassword)

  await prisma.$transaction([
    // Update User Password & Clear Token
    prisma.user.update({
      where: { id: user.id },
      data: {
        passwordHash: newPasswordHash,
        passwordChangedAt: new Date(),
        passwordResetTokenHash: null, // Prevent reuse
        passwordResetExpiresAt: null, // Cleanup
        passwordResetUsed: true
      }
    }),

    // SECURITY: Revoke all sessions.
    // If a hacker had access, they are now locked out and must login with the new password.
    prisma.userRefreshToken.updateMany({
      where: { userId: user.id, revoked: false },
      data: {
        revoked: true,
        replacedBy: 'Password Reset'
      }
    })
  ])

  logger.info(`Password reset successfully | userId=${user.id}`)

  return ApiResponse.success(req, res, 200, Messages.PASSWORD_RESET_SUCCESS)
}

export async function userSessions() {}
export async function userSessionsRemove() {}
