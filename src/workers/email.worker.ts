import { Worker, Job } from 'bullmq'
import { logger } from '../configs/logger'
import { redisBull } from '../configs/redisBull'
import { config } from '../configs/config'
import { sendEmail } from '../utils/sendEmail'
import { EmailRenderService } from '../services/emailRenderService' // Import the registry
import { EmailJobData, EmailJobName } from '../queues/email.queue'

const processor = async (
  job: Job<EmailJobData, unknown, EmailJobName>
): Promise<void> => {
  logger.info(`Processing job: ${job.name}`, { jobId: job.id })

  const { to } = job.data

  try {
    // 1. Delegate Rendering to the Service
    // This keeps the worker file clean and "dumb"
    const { html, subject } = await EmailRenderService.render(job.data)

    // 2. Send Email
    await sendEmail({
      to,
      subject,
      html
    })

    logger.info(`Email sent successfully: ${job.name}`, {
      email: to,
      jobId: job.id
    })
  } catch (error) {
    logger.error(`Failed to process job ${job.name}:`, error)
    throw error
  }
}

const emailWorker = new Worker<EmailJobData, unknown, EmailJobName>(
  'emailQueue',
  processor,
  {
    connection: redisBull,
    concurrency: Number(config.WORKERS.EMAIL_CONCURRENCY) || 5
  }
)

// --- Worker Event Listeners (Observability) ---

emailWorker.on('active', (job) => {
  logger.info('Job active', { jobId: job.id, name: job.name })
})

emailWorker.on('failed', (job, err) => {
  logger.error(`Job ${job?.id} failed`, {
    name: job?.name,
    error: err?.message
  })
})

emailWorker.on('completed', (job) => {
  logger.info(`Job completed: ${job.id}`)
})

emailWorker.on('error', (err) => {
  logger.error('Worker error', { error: err?.message })
})

emailWorker.on('drained', () => {
  logger.info('Queue drained (no waiting jobs)')
})

// Graceful Shutdown
process.on('SIGINT', async () => {
  logger.info('SIGINT: shutting down worker gracefully...')
  await emailWorker.close()
  await redisBull.quit()
  logger.info('Worker cleanup done. Exiting.')
  process.exit(0)
})

export default emailWorker
