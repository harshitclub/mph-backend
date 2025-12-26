import express, { Application } from 'express'
import dotenv from 'dotenv'
dotenv.config()

// 1. External Middleware
import cors from 'cors'
import helmet from 'helmet'
import cookieParser from 'cookie-parser'
import compression from 'compression'
import hpp from 'hpp'

// 2. Internal Configs
import { config } from './configs/config'
import { logger } from './configs/logger'
import { prisma } from './configs/prisma'
import redisCache from './configs/redisCache'
import { morganMiddleware } from './configs/morganMiddleware'

// 3. Application Middleware
import { errorHandler } from './middlewares/errorHandler'
import { notFound } from './controllers/v1/system.controllers'

// 4. Routes
import systemRoutesV1 from './routes/v1/system.routes'
import userRoutesV1 from './routes/v1/user.routes'
import adminRoutesV1 from './routes/v1/admin.routes'

const app: Application = express()

// --- MIDDLEWARE ---

app.use(helmet())

app.use(
  cors({
    origin: (origin, callback) => {
      const allowedOrigins = [config.FRONTEND_URL, 'http://localhost:3000']
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true)
      } else {
        callback(new Error('Not allowed by CORS'))
      }
    },
    credentials: true
  })
)

app.use(morganMiddleware)
app.use(express.json({ limit: '10kb' }))
app.use(express.urlencoded({ extended: true, limit: '10kb' }))
app.use(cookieParser())
app.use(compression())
app.use(hpp())
app.disable('x-powered-by')

// --- ROUTES ---

app.use('/api/v1/system', systemRoutesV1)
app.use('/api/v1/users', userRoutesV1)
app.use('/api/v1/admins', adminRoutesV1)

// --- ERROR HANDLING ---

app.use(notFound)
app.use(errorHandler)

// --- SERVER ---

const PORT = Number(config.PORT) || 3002
const HOST = '0.0.0.0'

const server = app.listen(PORT, HOST, () => {
  logger.info(`🚀 Server ${process.pid} running in ${config.ENV} mode`)
  // Make it clickable in VS Code
  if (config.ENV === 'development') {
    logger.info(`🔗 Local: http://localhost:${PORT}`)
  } else {
    logger.info(`🔗 Network: http://${HOST}:${PORT}`)
  }
})

// --- SHUTDOWN ---

const gracefulShutdown = async (signal: string) => {
  try {
    logger.warn(`${signal} received - shutting down gracefully...`)

    server.close(async () => {
      // Close Database Connections
      const cleanup = [
        prisma
          .$disconnect()
          .catch((e) => logger.error('Prisma disconnect failed', e)),
        redisCache.quit().catch((e) => logger.error('Redis quit failed', e))
      ]

      await Promise.all(cleanup)

      logger.info('Cleanup complete. Exiting.')
      process.exit(0)
    })

    // Force kill if cleanup hangs
    setTimeout(() => {
      logger.error('Forcing shutdown after timeout')
      process.exit(1)
    }, 10000).unref()
  } catch (error) {
    logger.error('Error during shutdown', error)
    process.exit(1)
  }
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'))
process.on('SIGINT', () => gracefulShutdown('SIGINT'))

process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled Rejection at:', reason)
  process.exit(1)
})
process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception:', err)
  process.exit(1)
})
