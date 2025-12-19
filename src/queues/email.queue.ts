import { Queue, JobsOptions } from 'bullmq'
import crypto from 'crypto'
import { redisBull } from '../configs/redisBull'

// 1. Define Names
export type EmailJobName =
  | 'verificationEmail'
  | 'resetPasswordEmail'
  | 'reVerificationEmail'
// Future: | 'invoiceEmail' | 'welcomeNewTeamMember'

// 2. Define Payloads for EACH email type
export interface VerificationEmailPayload {
  type: 'verificationEmail'
  to: string
  data: {
    firstName: string
    token: string
  }
}

export interface ResetPasswordPayload {
  type: 'resetPasswordEmail'
  to: string
  data: {
    firstName: string
    token: string
  }
}

export interface ReVerificationPayload {
  type: 'reVerificationEmail'
  to: string
  data: {
    firstName: string
    token: string
  }
}

// Future example:
// export interface InvoiceEmailPayload {
//   type: 'invoiceEmail'
//   to: string
//   data: { amount: number; currency: string }
// }

// 3. Create the Master Union Type
export type EmailJobData =
  | VerificationEmailPayload
  | ResetPasswordPayload
  | ReVerificationPayload

export const emailQueue = new Queue<EmailJobData, unknown, EmailJobName>(
  'emailQueue',
  {
    connection: redisBull,
    defaultJobOptions: {
      attempts: 3,
      backoff: { type: 'exponential', delay: 5000 },
      removeOnComplete: { age: 3600 },
      removeOnFail: { age: 24 * 3600 }
    }
  }
)

/**
 * Generate a unique ID based on the payload to prevent duplicates
 */
function buildJobId(payload: EmailJobData) {
  const hash = crypto
    .createHash('sha256')
    .update(JSON.stringify(payload))
    .digest('hex')
    .slice(0, 16)
  return `${payload.type}-${hash}`
}

export async function enqueueEmail(
  payload: EmailJobData,
  opts?: JobsOptions & { jobId?: string }
) {
  const jobId = opts?.jobId ?? buildJobId(payload)
  // We use payload.type as the job name for clarity
  return emailQueue.add(payload.type, payload, { ...opts, jobId })
}
