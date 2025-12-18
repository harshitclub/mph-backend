import { NextFunction, Request, Response } from 'express'
import { JwtPayload, TokenExpiredError } from 'jsonwebtoken'
import { Messages } from '../configs/messages'
import { AppError } from '../utils/appError'
import { verifyAccessToken } from '../utils/tokens/accessToken'
import { prisma } from '../configs/prisma'
import { logger } from '../configs/logger'

export async function authenticateAdmin(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    // 1. Extract Authorization Header
    const authHeader = req.headers.authorization
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new AppError(Messages.TOKEN_REQUIRED, 401)
    }

    const token = authHeader.split(' ')[1]
    if (!token) {
      throw new AppError(Messages.TOKEN_INVALID, 401)
    }

    // 2. Verify Token (Strict Typing)
    // We use JwtPayload to read the raw 'sub' field
    let decoded: JwtPayload | null = null

    try {
      const verificationResult = verifyAccessToken(token)

      if (typeof verificationResult === 'string') {
        throw new AppError(Messages.TOKEN_INVALID, 401)
      }

      decoded = verificationResult
    } catch (err) {
      if (err instanceof TokenExpiredError) {
        throw new AppError(Messages.TOKEN_EXPIRED, 401)
      }
      throw new AppError(Messages.TOKEN_INVALID, 401)
    }

    if (!decoded || !decoded.sub) {
      throw new AppError(Messages.TOKEN_INVALID, 401)
    }

    // 3. The Critical Difference: Query the ADMIN Table
    // We do NOT look at prisma.user. We only look at prisma.admin.
    const admin = await prisma.admin.findUnique({
      where: { id: decoded.sub }, // Use 'sub' to find the admin
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        role: true
        // isSuperAdmin: true // Uncomment if you need this logic later
      }
    })

    // 4. Verify Admin Status
    // If the ID in the token does not exist in the Admin table, deny access.
    // This stops regular Users (who have valid tokens) from accessing Admin routes.
    if (!admin || admin.role !== 'ADMIN') {
      logger.warn(
        `Access Denied: Non-admin tried to access admin route | id=${decoded.sub}`
      )
      throw new AppError(Messages.ACCESS_DENIED, 403)
    }

    // 5. Attach Admin Identity (The "Bridge")
    // We map the Admin DB fields to your standard AccessTokenPayload interface.
    req.user = {
      id: admin.id,
      email: admin.email,
      name: `${admin.firstName} ${admin.lastName}`,
      role: admin.role // This will be 'ADMIN'
    }

    return next()
  } catch (error) {
    if (error instanceof AppError) {
      return next(error)
    }
    logger.warn(`Admin Auth middleware error | ip=${req.ip} | error=${error}`)
    return next(error)
  }
}
