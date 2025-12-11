import { Request, Response } from 'express'
import { JwtPayload } from 'jsonwebtoken'

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
import {
  generateVerificationTokenRaw,
  timingSafeMatch
} from '../../utils/tokens/verificationToken'
import { sha256Hex } from '../../utils/tokens/sha256Hex'

// Email
import { emailQueue } from '../../queues/email.queue'
import { verifyEmailTemplate } from '../../emails/templates/auth/verify-email'

// Prisma Types
import { Prisma } from '../../generated/prisma/client'
import redisCache from '../../configs/redisCache'
import { loginValidator } from '../../validators/common.validator'
import { isObject } from '../../utils/isObject'
import { getUser } from '../../utils/getUser'

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
  // Validate request payload
  const parsed = await signupUserValidator.safeParseAsync(req.body)
  if (!parsed.success) {
    throw new AppError(Messages.VALIDATION_FAILED, 400)
  }

  const { firstName, lastName, email, password } = parsed.data

  // Hash the user password before saving
  const passwordHash = await hashPassword(password)

  // Generate email verification token (raw sent to user, hash stored in DB)
  const { raw: rawToken, expiresAt } = generateVerificationTokenRaw(15)
  const tokenHash = sha256Hex(rawToken)

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

    // Send verification email (async background job)
    await emailQueue.add('verificationEmail', {
      to: user.email,
      subject: 'Verify Your Email',
      html: verifyEmailTemplate({
        name: user.firstName,
        token: rawToken
      })
    })

    // Log successful account creation (mask email for privacy)
    logger.info(
      `${Messages.USER_CREATED} | userId=${user.id} | email=${maskEmail(user.email)} | ip=${req.ip}`
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
        `Signup attempt with existing email | email=${maskEmail(email)} | ip=${req.ip}`
      )
      throw new AppError(Messages.USER_ALREADY_EXISTS, 400)
    }

    const errorMessage = err instanceof Error ? err.message : String(err)

    // Log unexpected errors
    logger.error(
      `Signup failed | email=${maskEmail(email)} | error=${errorMessage}`
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
  const token = String(req.query.token ?? req.body?.token ?? '')

  if (!token) {
    throw new AppError(Messages.MISSING_VERIFICATION_TOKEN, 400)
  }

  // Convert raw token to hash to compare with stored DB value
  const tokenHash = sha256Hex(token)

  // Look up the user associated with this token (not expired and unused)
  const user = await prisma.user.findFirst({
    where: {
      emailVerificationTokenHash: tokenHash,
      emailVerificationUsed: false,
      emailVerificationExpiresAt: { gt: new Date() }
    },
    select: {
      id: true,
      email: true,
      firstName: true,
      emailVerificationTokenHash: true,
      emailVerificationExpiresAt: true,
      emailVerificationUsed: true,
      emailVerified: true
    }
  })

  // If no match, return generic invalid link message
  if (!user) {
    logger.warn(`Email verify failed: invalid/expired token`)
    return ApiResponse.error(req, res, 400, Messages.VERIFICATION_TOKEN_INVALID)
  }

  // Timing-safe comparison (prevents leaking token validity via timing attacks)
  const matches = timingSafeMatch(token, user.emailVerificationTokenHash!)

  if (!matches) {
    logger.warn(`Email verify failed: timingSafeMatch mismatch`)
    return ApiResponse.error(req, res, 400, Messages.VERIFICATION_TOKEN_INVALID)
  }

  // Mark verification as complete and invalidate token
  await prisma.user.update({
    where: { id: user.id },
    data: {
      emailVerified: true,
      emailVerificationUsed: true,
      emailVerificationTokenHash: null, // Null out hash (can't reuse)
      emailVerificationExpiresAt: null // Null expiry (cleanup)
    }
  })

  // Log verification success
  logger.info(`Email verified | userId=${user.id}`)

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

  // 2. Fetch user
  const user = await prisma.user.findUnique({
    where: { email },
    select: {
      id: true,
      firstName: true,
      lastName: true,
      email: true,
      emailVerified: true,
      phone: true,
      isDisabled: true,
      createdAt: true,
      profile: true,
      role: true,
      passwordHash: true,
      failedLogins: true
    }
  })

  if (!user) throw new AppError(Messages.LOGIN_FAILED, 401)
  if (user.isDisabled) throw new AppError(Messages.ACCOUNT_LOCKED, 403)

  // 3. Verify password
  const isPasswordValid = await comparePassword(password, user.passwordHash)

  // 4. Handle incorrect password attempts
  if (!isPasswordValid) {
    const updated = await prisma.user.update({
      where: { id: user.id },
      data: { failedLogins: { increment: 1 } },
      select: { failedLogins: true }
    })

    // Lock account if threshold exceeded
    if (updated.failedLogins >= MAX_FAILED_LOGIN) {
      await prisma.user.update({
        where: { id: user.id },
        data: { isDisabled: true }
      })
      logger.warn(
        `Account locked due to repeated failed logins | userId=${user.id}`
      )
      throw new AppError(Messages.ACCOUNT_LOCKED, 403)
    }

    logger.warn(
      `Login failed: wrong password | userId=${user.id} | attempts=${updated.failedLogins}`
    )
    throw new AppError(Messages.LOGIN_FAILED, 401)
  }

  // 5. Password valid → Generate tokens
  const accessToken = generateAccessToken({ sub: user.id })
  const { token: refreshJwt, jti } = generateRefreshTokenWithJti({
    sub: user.id
  })
  const refreshJtiHash = sha256Hex(jti)
  const refreshExpiresAt = new Date(Date.now() + config.COOKIE.REFRESH_TTL_MS)

  const userAgent = req.get('user-agent') ?? null
  const ip =
    req.ip ?? (req.headers['x-forwarded-for'] as string | undefined) ?? null

  // 6. Single-session: Revoke old refresh tokens and store new one
  await prisma.$transaction([
    // revoke old tokens
    prisma.userRefreshToken.updateMany({
      where: { userId: user.id, revoked: false },
      data: { revoked: true }
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
    `Login success | userId=${user.id} | email=${maskEmail(user.email)} | ip=${req.ip}`
  )
  return ApiResponse.success(req, res, 200, Messages.LOGIN_SUCCESS, safeUser)
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

  // 1) Must have refresh cookie to proceed
  if (!rawRefresh) {
    throw new AppError(Messages.TOKEN_INVALID, 401)
  }

  // 2) Verify refresh JWT
  let decodedToken: string | JwtPayload

  try {
    decodedToken = verifyRefreshToken(rawRefresh)
  } catch {
    throw new AppError(Messages.TOKEN_INVALID, 401)
  }

  // Ensure decoded token is an object with jti + sub
  if (typeof decodedToken !== 'object' || decodedToken === null) {
    throw new AppError(Messages.TOKEN_INVALID, 401)
  }

  const jtiValue = decodedToken.jti
  const subValue = decodedToken.sub

  if (typeof jtiValue !== 'string' || !jtiValue.trim()) {
    throw new AppError(Messages.TOKEN_INVALID, 401)
  }
  if (typeof subValue !== 'string' || !subValue.trim()) {
    throw new AppError(Messages.TOKEN_INVALID, 401)
  }

  const jti = jtiValue
  const userId = subValue

  // 3) Hash jti and lookup in database
  const tokenHash = sha256Hex(jti)

  const existing = await prisma.userRefreshToken.findUnique({
    where: { tokenHash }
  })

  // No matching token → revoke all and fail
  if (!existing) {
    try {
      await prisma.userRefreshToken.updateMany({
        where: { userId },
        data: { revoked: true }
      })
    } catch {
      // ignore update errors while continuing to fail request
    }
    throw new AppError(Messages.TOKEN_INVALID, 401)
  }

  // Token is known but revoked → revoke everything and fail
  if (existing.revoked) {
    await prisma.userRefreshToken.updateMany({
      where: { userId: existing.userId },
      data: { revoked: true }
    })
    throw new AppError(Messages.TOKEN_INVALID, 401)
  }

  // Token expired → mark revoked and fail
  if (existing.expiresAt <= new Date()) {
    await prisma.userRefreshToken.update({
      where: { id: existing.id },
      data: { revoked: true }
    })
    throw new AppError(Messages.TOKEN_INVALID, 401)
  }

  // 4) Rotate refresh token (replace old one with new one)
  const { token: newRefreshJwt, jti: newJti } = generateRefreshTokenWithJti({
    sub: userId
  })
  const newHash = sha256Hex(newJti)
  const newExpiresAt = new Date(Date.now() + REFRESH_TTL_MS)
  const userAgent = req.get('user-agent') ?? null
  const ip =
    req.ip ?? (req.headers['x-forwarded-for'] as string | undefined) ?? null

  await prisma.$transaction([
    prisma.userRefreshToken.update({
      where: { id: existing.id },
      data: { revoked: true, replacedBy: newHash }
    }),
    prisma.userRefreshToken.create({
      data: {
        userId,
        tokenHash: newHash,
        expiresAt: newExpiresAt,
        userAgent,
        ip
      }
    })
  ])

  // 5) Issue new access token
  const accessToken = generateAccessToken({ sub: userId })

  // 6) Send new refresh token cookie
  res.cookie(REFRESH_COOKIE_NAME, newRefreshJwt, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: REFRESH_COOKIE_PATH,
    maxAge: REFRESH_TTL_MS
  })

  // 7) Log rotation success
  logger.info(`Refresh success | userId=${userId} | ip=${req.ip}`)

  // 8) Send new access token back to client
  return ApiResponse.success(
    req,
    res,
    200,
    Messages.TOKEN_REFRESHED ?? 'Token refreshed',
    {
      accessToken
    }
  )
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

  if (!parsed.success) throw new AppError(Messages.VALIDATION_FAILED, 400)

  const updateData = parsed.data

  if (Object.keys(updateData).length === 0) {
    throw new AppError(Messages.NO_VALID_FIELD, 400)
  }

  // read once (needed to merge profile)
  const existing = await prisma.user.findUnique({
    where: {
      id
    },
    select: {
      profile: true
    }
  })

  if (!existing) throw new AppError(Messages.NOT_FOUND, 404)

  const data: Record<string, unknown> = {}

  // presence-based assignment (allows empty string if schema permits it)
  if ('firstName' in updateData) data.firstName = updateData.firstName
  if ('lastName' in updateData) data.lastName = updateData.lastName
  if ('username' in updateData) data.username = updateData.username
  if ('phone' in updateData) data.phone = updateData.phone

  // merge profile only if client sent it
  if ('profile' in updateData && updateData.profile) {
    const current = isObject(existing.profile) ? existing.profile : {}
    data.profile = { ...current, ...updateData.profile }
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
        profile: true,
        email: true
      }
    })
  } catch (err) {
    // Prisma unique field error
    if (
      err instanceof Prisma.PrismaClientKnownRequestError &&
      err.code === 'P2002'
    ) {
      throw new AppError('Username already taken', 409)
    }
    throw err
  }

  const cacheKey = `user:${id}`
  await redisCache.set(cacheKey, JSON.stringify(updatedUser), 'EX', 3600)

  return ApiResponse.success(req, res, 200, Messages.USER_UPDATED, updatedUser)
}
export async function userChangePassword() {}
export async function userRequestVerification() {}
export async function userRequestResetPassword() {}
export async function userResetPassword() {}
