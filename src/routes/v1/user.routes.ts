import express from 'express'
import {
  refreshHandler,
  userChangePassword,
  userLogin,
  userLogout,
  userProfile,
  userRequestResetPassword,
  userRequestVerification,
  userResetPassword,
  userSignup,
  userUpdate,
  userVerifyEmail
} from '../../controllers/v1/user.controllers'
import { asyncHandler } from '../../middlewares/asyncHandler'
import { authenticateUser } from '../../middlewares/authenticateUser'

const userRoutesV1 = express.Router()

userRoutesV1.post('/signup', asyncHandler(userSignup))
userRoutesV1.get('/verify', asyncHandler(userVerifyEmail))
userRoutesV1.post('/login', asyncHandler(userLogin))
userRoutesV1.post('/logout', authenticateUser, asyncHandler(userLogout))
userRoutesV1.get('/me', authenticateUser, asyncHandler(userProfile))
userRoutesV1.patch('/me', authenticateUser, asyncHandler(userUpdate))
userRoutesV1.post('/refresh', asyncHandler(refreshHandler))
userRoutesV1.patch(
  '/change-password',
  authenticateUser,
  asyncHandler(userChangePassword)
)
userRoutesV1.post(
  '/resend-verification',
  authenticateUser,
  asyncHandler(userRequestVerification)
)
userRoutesV1.post('/forget-password', asyncHandler(userRequestResetPassword))
userRoutesV1.post('/reset-password', asyncHandler(userResetPassword))

export default userRoutesV1
