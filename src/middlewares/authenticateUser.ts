import { NextFunction, Request, Response } from 'express'
import { TokenExpiredError, JwtPayload } from 'jsonwebtoken'
import { Messages } from '../configs/messages'
import { AppError } from '../utils/appError'
import { verifyAccessToken } from '../utils/tokens/accessToken'
import { prisma } from '../configs/prisma'
import { logger } from '../configs/logger'
import { AccessTokenPayload } from '../types/accessTokenPayload'

declare module 'express-serve-static-core' {
  interface Request {
    user?: AccessTokenPayload
  }
}

export async function authenticateUser(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const authHeader = req.headers.authorization
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new AppError(Messages.TOKEN_REQUIRED, 401)
    }

    console.log(authHeader)

    const token = authHeader.split(' ')[1]
    if (!token) {
      throw new AppError(Messages.TOKEN_INVALID, 401)
    }

    // 1. Use standard JwtPayload for the raw decoded token
    // (This contains 'sub', 'iat', 'exp', etc.)
    let decoded: JwtPayload | null = null

    try {
      const verificationResult = verifyAccessToken(token)

      // verifyAccessToken returns string | JwtPayload. We handle string (invalid) first.
      if (typeof verificationResult === 'string') {
        throw new AppError(Messages.TOKEN_INVALID, 401)
      }

      // Safe to assign because verificationResult is now guaranteed to be an object
      decoded = verificationResult
    } catch (err) {
      if (err instanceof TokenExpiredError) {
        throw new AppError(Messages.TOKEN_EXPIRED, 401)
      }
      throw new AppError(Messages.TOKEN_INVALID, 401)
    }

    // 2. Check for .sub (Standard JWT Subject field)
    if (!decoded || !decoded.sub) {
      throw new AppError(Messages.TOKEN_INVALID, 401)
    }

    // 3. Find User using 'sub'
    const user = await prisma.user.findUnique({
      where: { id: decoded.sub }, // .sub is a string in JwtPayload
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        role: true,
        isDisabled: true
      }
    })

    if (!user || user.isDisabled) {
      throw new AppError(Messages.ACCOUNT_LOCKED, 403)
    }

    // 4. Map DB result to your custom AccessTokenPayload interface
    // This bridges the gap between the token structure (sub) and your app structure (id)
    req.user = {
      id: user.id,
      email: user.email,
      name: `${user.firstName} ${user.lastName}`,
      role: user.role
    }

    return next()
  } catch (error) {
    if (error instanceof AppError) {
      return next(error)
    }
    logger.warn(`Auth middleware error | ip=${req.ip} | error=${error}`)
    return next(error)
  }
}
