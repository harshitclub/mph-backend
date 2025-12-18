import express from 'express'
import {
  adminChangePassword,
  adminChangeUserStatus,
  adminDeleteUser,
  adminGetUser,
  adminGetUsers,
  adminLogin,
  adminLogout,
  adminMakeUser,
  adminProfile,
  adminRequestResetPassword,
  adminResetPassword,
  adminSignup,
  adminUpdate,
  adminUpdateUser,
  refreshHandler
} from '../../controllers/v1/admin.controllers'
import { asyncHandler } from '../../middlewares/asyncHandler'
import { authenticateAdmin } from '../../middlewares/authenticateAdmin'

const adminRoutesV1 = express.Router()

adminRoutesV1.post('/signup', asyncHandler(adminSignup))
adminRoutesV1.post('/login', asyncHandler(adminLogin))
adminRoutesV1.post('/logout', authenticateAdmin, asyncHandler(adminLogout))
adminRoutesV1.get('/me', authenticateAdmin, asyncHandler(adminProfile))
adminRoutesV1.patch('/me', asyncHandler(adminUpdate))
adminRoutesV1.post('/refresh-token', asyncHandler(refreshHandler))
adminRoutesV1.patch(
  '/change-password',
  authenticateAdmin,
  asyncHandler(adminChangePassword)
)
adminRoutesV1.post('/forget-password', asyncHandler(adminRequestResetPassword))
adminRoutesV1.post('/reset-password', asyncHandler(adminResetPassword))
adminRoutesV1.post('/users', authenticateAdmin, asyncHandler(adminMakeUser))
adminRoutesV1.get('/users', authenticateAdmin, asyncHandler(adminGetUsers))
adminRoutesV1.get('/users/:id', authenticateAdmin, asyncHandler(adminGetUser))
adminRoutesV1.patch(
  '/users/:id/status',
  authenticateAdmin,
  asyncHandler(adminChangeUserStatus)
)
adminRoutesV1.patch(
  '/users/:id',
  authenticateAdmin,
  asyncHandler(adminUpdateUser)
)
adminRoutesV1.delete(
  '/users/:id',
  authenticateAdmin,
  asyncHandler(adminDeleteUser)
)

export default adminRoutesV1
