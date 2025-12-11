import { PrismaClient } from '../generated/prisma/client'
import { PrismaNeon } from '@prisma/adapter-neon'
import dotenv from 'dotenv'

dotenv.config()
const connectionString = `${process.env.DATABASE_URL}`

const adapter = new PrismaNeon({ connectionString })

const globalForPrisma = globalThis as unknown as {
  prisma?: PrismaClient
}

export const prisma = globalForPrisma.prisma ?? new PrismaClient({ adapter })

if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = prisma

// import { PrismaClient } from '../generated/prisma/client'
// import { logger } from './logger'

// const globalForPrisma = globalThis as unknown as {
//   prisma?: PrismaClient
// }

// export const prisma =
//   globalForPrisma.prisma ??
//   new PrismaClient({
//     log:
//       process.env.NODE_ENV === 'development'
//         ? ['query', 'error', 'warn']
//         : ['error']
//   })

// if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = prisma

// logger.info(`Prisma Client initialized for ${process.env.NODE_ENV} mode.`)
