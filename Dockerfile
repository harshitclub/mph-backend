# ----------------------------
# STAGE 1: BUILDER
# ----------------------------
FROM node:lts-alpine AS builder
WORKDIR /app

# Install dependencies (including devDependencies for build)
COPY package*.json ./
COPY prisma ./prisma/
RUN npm ci

# Generate Prisma Client & Build
RUN npx prisma generate
COPY . .
RUN npm run build

# ----------------------------
# STAGE 2: RUNNER (Production)
# ----------------------------
FROM node:lts-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production

# Install only production dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy built artifacts from builder
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/prisma ./prisma

# Important: Re-generate Prisma for the specific OS (Alpine Linux)
RUN npx prisma generate

EXPOSE 3002
CMD ["node", "dist/index.js"]