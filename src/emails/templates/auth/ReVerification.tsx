import * as React from 'react'
import { Text, Button, Section, Link } from '@react-email/components'
import { BaseLayout } from '../../components/BaseLayout'

interface ReVerificationEmailProps {
  firstName: string
  verifyUrl: string
}

export const ReVerification = ({
  firstName = 'User',
  verifyUrl = 'https://example.com'
}: ReVerificationEmailProps) => {
  return (
    <BaseLayout
      previewText="Here is the verification link you requested."
      heading="Verify your email"
    >
      <Text style={paragraph}>
        Hello <strong>{firstName}</strong>,
      </Text>

      <Text style={paragraph}>
        We received a request to verify the email address associated with your{' '}
        <strong>MPH</strong> account.
      </Text>

      <Text style={paragraph}>
        To complete the verification process, please click the button below:
      </Text>

      <Section style={btnContainer}>
        <Button style={button} href={verifyUrl}>
          Verify Email Address
        </Button>
      </Section>

      <Text style={paragraph}>
        If you didn't request this email, you can safely ignore it.
      </Text>

      <Text style={paragraph}>
        Or copy and paste this URL into your browser:
        <br />
        <Link href={verifyUrl} style={link}>
          {verifyUrl}
        </Link>
      </Text>
    </BaseLayout>
  )
}

// --- STYLES ---

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
ReVerification.PreviewProps = {
  firstName: 'John',
  verifyUrl: 'https://mph-app.com/verify?token=123456'
}

export default ReVerification
