import { render } from '@react-email/render'
import { config } from '../configs/config'

// Import Templates
import { WelcomeEmail } from '../emails/templates/auth/WelcomeEmail'
import { ResetPassword } from '../emails/templates/auth/ResetPassword'

// Import Types
import { EmailJobData } from '../queues/email.queue'

interface RenderResult {
  html: string
  subject: string
}

export const EmailRenderService = {
  async render(jobData: EmailJobData): Promise<RenderResult> {
    switch (jobData.type) {
      case 'verificationEmail': {
        const { firstName, token } = jobData.data
        const verifyUrl = `${config.FRONTEND_URL}/verify?token=${token}`

        const html = await render(
          <WelcomeEmail firstName={firstName} verifyUrl={verifyUrl} />
        )
        return { html, subject: 'Verify your email address' }
      }

      case 'resetPasswordEmail': {
        const { firstName, token } = jobData.data
        const resetUrl = `${config.FRONTEND_URL}/reset-password?token=${token}`

        const html = await render(
          <ResetPassword firstName={firstName} resetUrl={resetUrl} />
        )
        return { html, subject: 'Reset your password' }
      }

      // FUTURE: Easy to add new cases here without touching the Worker!
      // case 'invoiceEmail': ...

      default:
        // @ts-expect-error - exhaustive check safety
        throw new Error(`Unknown email type: ${jobData.type}`)
    }
  }
}
