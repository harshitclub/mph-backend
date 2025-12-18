import { z } from 'zod'
import { CustomValidators } from './custom.validator'

export const signupAdminValidator = z.object({
  firstName: CustomValidators.firstName,
  lastName: CustomValidators.lastName,
  email: CustomValidators.email,
  password: CustomValidators.password
})
