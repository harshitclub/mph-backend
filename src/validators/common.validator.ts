import z from 'zod'
import { CustomValidators } from './custom.validator'
import { Messages } from '../configs/messages'

// Login Validator
export const loginValidator = z.object({
  email: CustomValidators.email,
  password: CustomValidators.password
})

// Forget Password Validator
export const forgetPasswordValidator = z.object({
  email: CustomValidators.email
})

// Change Password Validator
export const changePasswordValidator = z.object({
  currentPassword: CustomValidators.password,
  newPassword: CustomValidators.password
})

export const resetPasswordValidator = z.object({
  newPassword: CustomValidators.password
})

// Verification Validator
export const verifyEmailValidator = z.object({
  token: z.string().min(1, Messages.MISSING_VERIFICATION_TOKEN)
})
