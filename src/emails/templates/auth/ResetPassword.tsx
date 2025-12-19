import * as React from 'react'
import { Text, Button, Section, Link } from '@react-email/components'
import { BaseLayout } from '../../components/BaseLayout'

interface ResetPasswordProps {
  resetUrl: string
  firstName: string
}

export const ResetPassword = ({
  resetUrl = 'https://example.com',
  firstName = 'User'
}: ResetPasswordProps) => {
  return (
    <BaseLayout previewText="Reset your password" heading="Reset Password">
      <Text style={paragraph}>
        Hi <strong>{firstName}</strong>,
      </Text>

      <Text style={paragraph}>
        We received a request to reset your password. If you didn't make this
        request, you can safely ignore this email.
      </Text>

      <Section style={btnContainer}>
        <Button style={button} href={resetUrl}>
          Reset My Password
        </Button>
      </Section>

      <Text style={paragraph}>
        This link will expire in <strong>15 minutes</strong> for your security.
      </Text>

      <Text style={paragraph}>
        If you're having trouble clicking the button, copy and paste the URL
        below:
        <br />
        <Link href={resetUrl} style={link}>
          {resetUrl}
        </Link>
      </Text>
    </BaseLayout>
  )
}

// --- STYLES (Consistent with WelcomeEmail) ---

const paragraph = {
  color: '#000000',
  fontSize: '14px',
  lineHeight: '24px',
  textAlign: 'left' as const,
  margin: '0 0 16px'
}

const btnContainer = {
  textAlign: 'center' as const,
  marginTop: '32px',
  marginBottom: '32px'
}

const button = {
  backgroundColor: '#e20b13', // MPH Brand Red
  borderRadius: '4px',
  color: '#ffffff',
  fontSize: '14px',
  fontWeight: '600',
  textDecoration: 'none',
  textAlign: 'center' as const,
  display: 'inline-block',
  padding: '12px 24px'
}

const link = {
  color: '#e20b13', // MPH Brand Red
  textDecoration: 'underline',
  fontSize: '12px',
  wordBreak: 'break-all' as const
}

// Default props for previewing in development
ResetPassword.PreviewProps = {
  firstName: 'John',
  resetUrl: 'https://mph-app.com/reset-password?token=xyz123'
}

export default ResetPassword
