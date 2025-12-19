import * as React from 'react'
import { Text, Button, Section, Link } from '@react-email/components'
import { BaseLayout } from '../../components/BaseLayout'

interface WelcomeEmailProps {
  firstName: string
  verifyUrl: string
}

export const WelcomeEmail = ({
  firstName = 'User',
  verifyUrl = 'https://example.com'
}: WelcomeEmailProps) => {
  return (
    <BaseLayout
      previewText="Welcome! Please verify your email address."
      heading="Confirm your email address"
    >
      <Text style={paragraph}>
        Hello <strong>{firstName}</strong>,
      </Text>

      <Text style={paragraph}>
        Thanks for joining <strong>MPH</strong>. We're excited to have you on
        board.
      </Text>

      <Text style={paragraph}>
        To verify your email address and start using your account, please click
        the button below:
      </Text>

      <Section style={btnContainer}>
        <Button style={button} href={verifyUrl}>
          Verify Email Address
        </Button>
      </Section>

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
WelcomeEmail.PreviewProps = {
  firstName: 'John',
  verifyUrl: 'https://mph-app.com/verify?token=123456'
}

export default WelcomeEmail
