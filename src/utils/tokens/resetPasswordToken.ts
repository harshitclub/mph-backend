import crypto from 'crypto'

export function generateResetPasswordTokenRaw(ttlMinutes = 15) {
  const raw = crypto.randomBytes(32).toString('hex')
  const expiresAt = new Date(Date.now() + ttlMinutes * 60 * 1000)

  return { raw, expiresAt }
}
