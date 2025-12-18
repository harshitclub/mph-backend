import { config } from '../../../configs/config'

export const verifyEmailTemplate = ({
  name,
  token
}: {
  name: string
  token: string
}) => {
  return `
    <html>
    <body>
    <h1>${name}</h1>
    <p><a href="${config.FRONTEND_URL}/verify/${token}">${token}</a></p>
    </body>
    </html>
    `
}
