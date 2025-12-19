import { Request, Response } from 'express'
import { logger } from '../../configs/logger'
import { Messages } from '../../configs/messages'
import { prisma } from '../../configs/prisma'
import { verifyEmailTemplate } from '../../emails/templates/auth/WelcomeEmail.tsx'
import { emailQueue } from '../../queues/email.queue'
import { AppError } from '../../utils/appError'
import { maskEmail } from '../../utils/mask'
import { comparePassword, hashPassword } from '../../utils/password'
import { sha256Hex } from '../../utils/tokens/sha256Hex'
import { generateVerificationTokenRaw } from '../../utils/tokens/verificationToken'
import { signupAdminValidator } from '../../validators/admin.validator'
import { ApiResponse } from '../../utils/apiResponse'
import { Prisma } from '../../generated/prisma/client'
import {
  changePasswordValidator,
  forgetPasswordValidator,
  loginValidator,
  resetPasswordValidator
} from '../../validators/common.validator'
import { generateAccessToken } from '../../utils/tokens/accessToken'
import { config } from '../../configs/config'
import {
  generateRefreshTokenWithJti,
  verifyRefreshToken
} from '../../utils/tokens/refreshToken'
import jwt, { JwtPayload } from 'jsonwebtoken'
import { getUser } from '../../utils/getUser'
import redisCache from '../../configs/redisCache'
import {
  signupUserValidator,
  updateUserValidator
} from '../../validators/user.validator'
import { isObject } from '../../utils/isObject'
import { generateResetPasswordTokenRaw } from '../../utils/tokens/resetPasswordToken'
import { resetPasswordEmailTemplate } from '../../emails/templates/auth/ResetPassword'

const { REFRESH_COOKIE_NAME, REFRESH_COOKIE_PATH, REFRESH_TTL_MS } =
  config.COOKIE

export async function adminSignup(req: Request, res: Response) {
  const adminSecret = req.headers['x-admin-secret']
  if (adminSecret !== process.env.ADMIN_CREATION_SECRET) {
    logger.warn(`Unauthorized admin signup attempt | ip=${req.ip}`)
    throw new AppError(Messages.UNAUTHORIZED, 403)
  }
  const parsed = await signupAdminValidator.safeParseAsync(req.body)
  if (!parsed.success) {
    // Optimization: Return specific field errors so frontend can show "Password too short"
    throw new AppError(Messages.VALIDATION_FAILED, 400)
  }

  const { firstName, lastName, email, password } = parsed.data

  const existingAdmin = await prisma.admin.findUnique({
    where: { email },
    select: { id: true }
  })

  if (existingAdmin) {
    logger.warn(
      `Signup blocked: Email already exists | email=${maskEmail(email)}`
    )
    throw new AppError(Messages.USER_ALREADY_EXISTS, 409) // 409 Conflict
  }

  const passwordHash = await hashPassword(password)

  const { raw: rawToken, expiresAt } = generateVerificationTokenRaw(15)
  const tokenHash = sha256Hex(rawToken)

  const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip

  try {
    const admin = await prisma.admin.create({
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
      await emailQueue.add('verificationEmail', {
        to: admin.email,
        subject: 'Verify Your Email',
        html: verifyEmailTemplate({
          name: admin.firstName,
          token: rawToken
        })
      })
    } catch (queueError) {
      logger.error(
        `Failed to queue verification email | userId=${admin.id} | error=${queueError}`
      )
    }

    logger.info(
      `${Messages.USER_CREATED} | userId=${admin.id} | email=${maskEmail(admin.email)} | ip=${ip}`
    )
    return ApiResponse.success(req, res, 201, Messages.USER_CREATED, {
      id: admin.id,
      email: admin.email,
      name: `${admin.firstName} ${admin.lastName}`,
      verified: admin.emailVerified
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

export async function adminVerifyEmail() {}

export async function adminLogin(req: Request, res: Response) {
  const parsed = await loginValidator.safeParseAsync(req.body)

  if (!parsed.success) {
    throw new AppError(Messages.VALIDATION_FAILED, 400)
  }

  const { email, password } = parsed.data

  const admin = await prisma.admin.findUnique({
    where: { email },
    select: {
      id: true,
      email: true,
      firstName: true,
      lastName: true,
      passwordHash: true,
      role: true,
      isSuperAdmin: true // Specific to Admin
    }
  })

  const validPassword =
    admin && (await comparePassword(password, admin.passwordHash))

  if (!admin || !validPassword) {
    logger.warn(`Admin login failed | email=${maskEmail(email)}`)
    throw new AppError(Messages.LOGIN_FAILED, 401)
  }

  const accessToken = generateAccessToken({
    sub: admin.id,
    role: admin.role,
    isSuperAdmin: admin.isSuperAdmin
  })

  const { token: refreshJwt, jti } = generateRefreshTokenWithJti({
    sub: admin.id
  })
  const refreshJtiHash = sha256Hex(jti)
  const refreshExpiresAt = new Date(Date.now() + config.COOKIE.REFRESH_TTL_MS)

  const userAgent = req.headers['user-agent'] || 'Unknown'
  const ip =
    (req.headers['x-forwarded-for'] as string)?.split(',')[0] ||
    req.ip ||
    'Unknown'

  await prisma.$transaction([
    prisma.adminRefreshToken.updateMany({
      where: { adminId: admin.id, revoked: false },
      data: { revoked: true, replacedBy: 'New Admin Login' }
    }),

    prisma.adminRefreshToken.create({
      data: {
        adminId: admin.id,
        tokenHash: refreshJtiHash,
        expiresAt: refreshExpiresAt,
        userAgent,
        ip
      }
    }),

    // We update 'lastLoginAt' but NOT failedLogins
    prisma.admin.update({
      where: { id: admin.id },
      data: { lastLoginAt: new Date() }
    })
  ])

  res.cookie(String(config.COOKIE.REFRESH_COOKIE_NAME), refreshJwt, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: REFRESH_COOKIE_PATH,
    maxAge: REFRESH_TTL_MS
  })

  logger.info(`Admin login success | adminId=${admin.id}`)

  const safeAdmin = {
    id: admin.id,
    email: admin.email,
    name: `${admin.firstName} ${admin.lastName}`,
    role: admin.role,
    isSuperAdmin: admin.isSuperAdmin,
    accessToken
  }

  return ApiResponse.success(req, res, 200, Messages.LOGIN_SUCCESS, safeAdmin)
}

export async function adminLogout(req: Request, res: Response) {
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
    // 3. Decode Token to get JTI
    const decoded = jwt.decode(refreshToken) as { jti?: string } | null

    if (decoded?.jti) {
      const tokenHash = sha256Hex(decoded.jti)

      // 4. Revoke Session in ADMIN Table
      // Using updateMany to avoid errors if the token is already gone.
      await prisma.adminRefreshToken.updateMany({
        where: { tokenHash: tokenHash },
        data: {
          revoked: true,
          replacedBy: 'Admin Logout'
        }
      })

      logger.info(`Admin Logout: Session revoked | hash=${tokenHash}`)
    }
  } catch (error) {
    // Fail safely without blocking the response
    logger.warn(`Admin Logout: DB cleanup failed | error=${String(error)}`)
  }

  // 5. Return Success
  return ApiResponse.success(req, res, 200, Messages.LOGOUT_SUCCESS)
}

export async function refreshHandler(req: Request, res: Response) {
  const rawRefresh = req.cookies?.[REFRESH_COOKIE_NAME]

  if (!rawRefresh) {
    throw new AppError(Messages.TOKEN_INVALID, 401)
  }

  // 2. Verify JWT Integrity
  let decoded: JwtPayload
  try {
    const result = verifyRefreshToken(rawRefresh)

    if (typeof result === 'string') {
      throw new AppError(Messages.TOKEN_INVALID, 401)
    }
    decoded = result as JwtPayload
  } catch {
    throw new AppError(Messages.TOKEN_INVALID, 401)
  }

  const { jti, sub: adminId } = decoded

  if (
    !adminId ||
    typeof adminId !== 'string' ||
    !jti ||
    typeof jti !== 'string'
  ) {
    throw new AppError(Messages.TOKEN_INVALID, 401)
  }

  const tokenHash = sha256Hex(jti)

  const [existingToken, admin] = await Promise.all([
    prisma.adminRefreshToken.findUnique({ where: { tokenHash } }),
    prisma.admin.findUnique({
      where: { id: adminId },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        role: true
      }
    })
  ])

  if (!existingToken) {
    logger.warn(`Admin reuse detection triggered | adminId=${adminId}`)
    // Revoke ALL sessions for this admin
    await prisma.adminRefreshToken.updateMany({
      where: { adminId },
      data: { revoked: true, replacedBy: 'Reuse Detection' }
    })
    throw new AppError(Messages.TOKEN_INVALID, 401)
  }

  if (existingToken.revoked || existingToken.expiresAt <= new Date()) {
    if (existingToken.revoked) {
      logger.warn(`Attempt to use revoked admin token | adminId=${adminId}`)
      // Revoke all other sessions as a precaution
      await prisma.adminRefreshToken.updateMany({
        where: { adminId },
        data: { revoked: true }
      })
    }
    throw new AppError(Messages.TOKEN_INVALID, 401)
  }

  if (!admin) {
    // Admin was deleted. Revoke session.
    await prisma.adminRefreshToken.update({
      where: { id: existingToken.id },
      data: { revoked: true, replacedBy: 'Admin Not Found' }
    })
    throw new AppError(Messages.ADMIN_NOT_FOUND, 401)
  }

  const { token: newRefreshJwt, jti: newJti } = generateRefreshTokenWithJti({
    sub: admin.id
  })

  const newHash = sha256Hex(newJti)
  const newExpiresAt = new Date(Date.now() + REFRESH_TTL_MS)

  const userAgent = req.headers['user-agent'] || 'Unknown'
  const ip =
    (req.headers['x-forwarded-for'] as string)?.split(',')[0] ||
    req.ip ||
    'Unknown'

  await prisma.$transaction([
    prisma.adminRefreshToken.update({
      where: { id: existingToken.id },
      data: { revoked: true, replacedBy: newHash }
    }),
    prisma.adminRefreshToken.create({
      data: {
        adminId: admin.id,
        tokenHash: newHash,
        expiresAt: newExpiresAt,
        userAgent,
        ip
      }
    })
  ])

  const accessToken = generateAccessToken({
    sub: admin.id
  })

  res.cookie(REFRESH_COOKIE_NAME, newRefreshJwt, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: REFRESH_COOKIE_PATH,
    maxAge: REFRESH_TTL_MS
  })

  logger.info(`Admin Refresh success | adminId=${admin.id}`)

  return ApiResponse.success(req, res, 200, Messages.TOKEN_REFRESHED, {
    accessToken
  })
}
export async function adminProfile(req: Request, res: Response) {
  const { id } = getUser(req)

  const cacheKey = `admin:${id}`

  const cached = await redisCache.get(cacheKey)
  if (cached) {
    const admin = JSON.parse(cached)
    return ApiResponse.success(req, res, 200, Messages.PROFILE_FETCHED, {
      admin,
      isCached: true
    })
  }

  const admin = await prisma.admin.findUnique({
    where: { id },
    select: {
      id: true,
      firstName: true,
      lastName: true,
      email: true,
      emailVerified: true,
      role: true,
      createdAt: true
    }
  })
  if (!admin) {
    throw new AppError(Messages.USER_NOT_FOUND, 404)
  }

  await redisCache.set(cacheKey, JSON.stringify(admin), 'EX', 3600)

  return ApiResponse.success(req, res, 200, Messages.PROFILE_FETCHED, {
    admin,
    isCached: false
  })
}
export async function adminUpdate() {}
export async function adminChangePassword(req: Request, res: Response) {
  const { id: userId } = getUser(req)

  const parsed = await changePasswordValidator.safeParseAsync(req.body)
  if (!parsed.success) {
    throw new AppError(Messages.VALIDATION_FAILED, 400)
  }

  const { currentPassword, newPassword } = parsed.data

  if (currentPassword === newPassword) {
    throw new AppError(Messages.SAME_PASSWORD, 400)
  }

  const admin = await prisma.admin.findUnique({
    where: { id: userId },
    select: { passwordHash: true, email: true }
  })

  if (!admin) {
    throw new AppError(Messages.USER_NOT_FOUND, 404)
  }

  const isValid = await comparePassword(currentPassword, admin.passwordHash)

  if (!isValid) {
    // We do NOT increment 'failedLogins' here because the user is already authenticated.
    // Just reject the request.
    throw new AppError(Messages.INVALID_OLD_PASSWORD, 400)
  }

  const newPasswordHash = await hashPassword(newPassword)

  await prisma.$transaction([
    prisma.admin.update({
      where: { id: userId },
      data: {
        passwordHash: newPasswordHash
      }
    }),

    // SECURITY: Revoke ALL other sessions except the current one.
    prisma.adminRefreshToken.updateMany({
      where: { adminId: userId },
      data: { revoked: true, replacedBy: 'Password Change' }
    })
  ])

  logger.info(
    `Password changed successfully | userId=${userId} | email=${admin.email}`
  )

  return ApiResponse.success(req, res, 200, Messages.PASSWORD_CHANGED)
}

export async function adminRequestResetPassword(req: Request, res: Response) {
  const parsed = await forgetPasswordValidator.safeParseAsync(req.body)

  if (!parsed.success) {
    throw new AppError(Messages.VALIDATION_FAILED, 400)
  }

  const { email } = parsed.data

  const admin = await prisma.admin.findUnique({
    where: { email },
    select: {
      id: true,
      email: true,
      firstName: true
    }
  })

  if (!admin) {
    logger.info(
      `Password reset requested for non-existent email | email=${maskEmail(email)}`
    )
    return ApiResponse.success(req, res, 200, Messages.PASSWORD_RESET_REQUESTED)
  }

  const { raw: rawToken, expiresAt } = generateResetPasswordTokenRaw(15)
  const tokenHash = sha256Hex(rawToken)

  await prisma.admin.update({
    where: { id: admin.id },
    data: {
      passwordResetTokenHash: tokenHash,
      passwordResetExpiresAt: expiresAt,
      passwordResetUsed: false
    }
  })

  try {
    await emailQueue.add('resetPasswordEmail', {
      to: admin.email,
      subject: 'Reset Your Password',
      html: resetPasswordEmailTemplate({
        name: admin.firstName,
        token: rawToken
      })
    })
    logger.info(`Reset Password email requested | userId=${admin.id}`)
  } catch (queueError) {
    logger.error(
      `Failed to queue reset password email | userId=${admin.id} | error=${queueError}`
    )
    throw new AppError(Messages.SERVER_ERROR, 500)
  }

  return ApiResponse.success(req, res, 200, Messages.PASSWORD_RESET_REQUESTED)
}
export async function adminResetPassword(req: Request, res: Response) {
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

  const admin = await prisma.admin.findFirst({
    where: {
      passwordResetTokenHash: tokenHash,
      passwordResetUsed: false,
      passwordResetExpiresAt: { gt: new Date() }
    },
    select: { id: true, email: true }
  })

  if (!admin) {
    logger.warn(`Password reset failed: Invalid or expired token`)
    throw new AppError(Messages.VERIFICATION_TOKEN_INVALID, 400)
  }

  const newPasswordHash = await hashPassword(newPassword)

  await prisma.$transaction([
    // Update User Password & Clear Token
    prisma.admin.update({
      where: { id: admin.id },
      data: {
        passwordHash: newPasswordHash,
        passwordResetTokenHash: null, // Prevent reuse
        passwordResetExpiresAt: null, // Cleanup
        passwordResetUsed: true
      }
    }),

    // SECURITY: Revoke all sessions.
    // If a hacker had access, they are now locked out and must login with the new password.
    prisma.adminRefreshToken.updateMany({
      where: { adminId: admin.id, revoked: false },
      data: {
        revoked: true,
        replacedBy: 'Password Reset'
      }
    })
  ])

  logger.info(`Password reset successfully | userId=${admin.id}`)

  return ApiResponse.success(req, res, 200, Messages.PASSWORD_RESET_SUCCESS)
}

export async function adminGetUsers(req: Request, res: Response) {
  const page = Number(req.query.page) || 1
  const limit = Number(req.query.limit) || 10
  const search = (req.query.search as string)?.trim() || ''

  const skip = (page - 1) * limit

  const cacheKey = `admin:users:page:${page}:limit:${limit}:search:${search}`

  const cachedData = await redisCache.get(cacheKey)

  if (cachedData) {
    const parsedData = JSON.parse(cachedData)
    return ApiResponse.success(req, res, 200, Messages.PROFILE_FETCHED, {
      ...parsedData,
      isCached: true
    })
  }

  const whereClause = search
    ? {
        OR: [
          { email: { contains: search, mode: 'insensitive' as const } },
          { firstName: { contains: search, mode: 'insensitive' as const } },
          { lastName: { contains: search, mode: 'insensitive' as const } },
          { username: { contains: search, mode: 'insensitive' as const } }
        ]
      }
    : {}

  const [users, total] = await prisma.$transaction([
    prisma.user.findMany({
      where: whereClause,
      skip,
      take: limit,
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        username: true,
        phone: true,
        role: true,
        isDisabled: true,
        createdAt: true
      }
    }),
    prisma.user.count({ where: whereClause })
  ])

  const totalPages = Math.ceil(total / limit)
  const hasNextPage = page < totalPages
  const hasPrevPage = page > 1

  const responseData = {
    users,
    meta: {
      total,
      page,
      limit,
      totalPages,
      hasNextPage,
      hasPrevPage
    }
  }

  await redisCache.set(cacheKey, JSON.stringify(responseData), 'EX', 60)
  return ApiResponse.success(req, res, 200, Messages.PROFILE_FETCHED, {
    ...responseData,
    isCached: false
  })
}

export async function adminGetUser(req: Request, res: Response) {
  const { id } = req.params

  if (!id) {
    throw new AppError(Messages.VALIDATION_FAILED, 400)
  }

  const cacheKey = `admin:user:${id}`

  const cachedData = await redisCache.get(cacheKey)

  if (cachedData) {
    const user = JSON.parse(cachedData)
    return ApiResponse.success(
      req,
      res,
      200,
      Messages.PROFILE_FETCHED,
      { user, isCached: true } // Inject flag
    )
  }

  const user = await prisma.user.findUnique({
    where: { id },
    select: {
      id: true,
      email: true,
      firstName: true,
      lastName: true,
      username: true,
      phone: true,
      role: true,
      isDisabled: true,
      createdAt: true,
      updatedAt: true,
      profile: true,
      emailVerified: true
    }
  })

  if (!user) {
    throw new AppError(Messages.USER_NOT_FOUND, 404)
  }

  await redisCache.set(cacheKey, JSON.stringify(user), 'EX', 60)

  return ApiResponse.success(
    req,
    res,
    200,
    Messages.PROFILE_FETCHED,
    { user, isCached: false } // Inject flag
  )
}

export async function adminChangeUserStatus(req: Request, res: Response) {
  const { id } = req.params
  if (!id) {
    throw new AppError(Messages.VALIDATION_FAILED, 400)
  }

  const user = await prisma.user.findUnique({
    where: { id },
    select: { id: true, isDisabled: true }
  })

  if (!user) {
    throw new AppError(Messages.USER_NOT_FOUND, 404)
  }

  const newStatus = !user.isDisabled

  const updatedUser = await prisma.user.update({
    where: { id },
    data: { isDisabled: newStatus },
    select: {
      id: true,
      email: true,
      firstName: true,
      lastName: true,
      isDisabled: true // Return the new status
    }
  })

  if (newStatus === true) {
    await prisma.userRefreshToken.updateMany({
      where: { userId: id },
      data: {
        revoked: true,
        replacedBy: 'Admin Ban' // Audit trail
      }
    })
  }

  const cacheKey = `admin:user:${id}`
  await redisCache.del(cacheKey)

  return ApiResponse.success(req, res, 200, Messages.USER_UPDATED, updatedUser)
}

export async function adminDeleteUser(req: Request, res: Response) {
  const { id } = req.params
  if (!id) {
    throw new AppError(Messages.VALIDATION_FAILED, 400)
  }

  const user = await prisma.user.findUnique({
    where: { id }
  })

  if (!user) {
    throw new AppError(Messages.USER_NOT_FOUND, 404)
  }

  await prisma.user.delete({
    where: { id }
  })

  const adminCacheKey = `admin:user:${id}` // Used by Admin Detail View
  const userCacheKey = `user:${id}`

  await Promise.all([
    redisCache.del(adminCacheKey),
    redisCache.del(userCacheKey)
  ])

  return ApiResponse.success(req, res, 200, Messages.USER_DELETED)
}

export async function adminMakeUser(req: Request, res: Response) {
  const parsed = await signupUserValidator.safeParseAsync(req.body)

  if (!parsed.success) {
    throw new AppError(Messages.VALIDATION_FAILED, 400)
  }

  const { email, password, firstName, lastName } = parsed.data

  const existingUser = await prisma.user.findUnique({
    where: { email }
  })

  if (existingUser) {
    throw new AppError(Messages.USER_ALREADY_EXISTS, 409)
  }

  const hashedPassword = await hashPassword(password)

  const newUser = await prisma.user.create({
    data: {
      email,
      firstName,
      lastName,
      passwordHash: hashedPassword,
      emailVerified: true, // Auto-verify since Admin created it
      role: 'USER', // Default role
      isDisabled: false // Active by default
    },
    select: {
      id: true,
      email: true,
      firstName: true,
      lastName: true,
      role: true,
      emailVerified: true,
      createdAt: true
    }
  })

  return ApiResponse.success(
    req,
    res,
    201, // 201 Created
    Messages.USER_CREATED,
    newUser
  )
}

export async function adminUpdateUser(req: Request, res: Response) {
  const { id } = req.params
  if (!id) throw new AppError(Messages.VALIDATION_FAILED, 400)

  const parsed = await updateUserValidator.safeParseAsync(req.body)

  if (!parsed.success) {
    throw new AppError(Messages.VALIDATION_FAILED, 400)
  }

  const updateData = parsed.data

  if (Object.keys(updateData).length === 0) {
    throw new AppError(Messages.NO_VALID_FIELD, 400)
  }

  const { profile, ...fields } = updateData

  const data: Prisma.UserUpdateInput = {}

  if (fields.firstName !== undefined) data.firstName = fields.firstName
  if (fields.lastName !== undefined) data.lastName = fields.lastName
  if (fields.username !== undefined) data.username = fields.username
  if (fields.phone !== undefined) data.phone = fields.phone

  if (profile) {
    const existing = await prisma.user.findUnique({
      where: { id },
      select: { profile: true }
    })

    if (!existing) throw new AppError(Messages.USER_NOT_FOUND, 404)

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
        isDisabled: true,
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
    if (
      err instanceof Prisma.PrismaClientKnownRequestError &&
      err.code === 'P2025'
    ) {
      throw new AppError(Messages.USER_NOT_FOUND, 404)
    }
    throw err
  }

  await Promise.all([
    redisCache.del(`admin:user:${id}`), // Clear Admin View
    redisCache.del(`user:${id}`) // Clear User App View
  ])

  return ApiResponse.success(req, res, 200, Messages.USER_UPDATED, updatedUser)
}
