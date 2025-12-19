import * as React from 'react'
import {
  Html,
  Head,
  Body,
  Container,
  Section,
  Text,
  Hr,
  Link,
  Preview,
  Font
} from '@react-email/components'

interface BaseLayoutProps {
  previewText: string
  heading?: string
  children: React.ReactNode
}

export const BaseLayout = ({
  previewText,
  heading,
  children
}: BaseLayoutProps) => {
  return (
    <Html>
      <Head>
        <Font
          fontFamily="Inter"
          fallbackFontFamily="Helvetica"
          webFont={{
            url: 'https://fonts.gstatic.com/s/inter/v12/UcCO3FwrK3iLTeHuS_fvQtMwCp50KnMw2boKoduKmMEVuLyfAZ9hjp-Ek-_EeA.woff2',
            format: 'woff2'
          }}
          fontWeight={400}
          fontStyle="normal"
        />
      </Head>
      <Preview>{previewText}</Preview>

      <Body style={main}>
        <Container style={container}>
          {/* MPH Logo Section (Hardcoded Text Logo) */}
          <Section style={{ marginTop: '32px' }}>
            <Text style={logo}>MPH</Text>
          </Section>

          {/* Optional Heading */}
          {heading && (
            <Section>
              <Text style={headingStyle}>{heading}</Text>
            </Section>
          )}

          {/* Main Content */}
          <Section style={content}>{children}</Section>

          {/* Footer Divider */}
          <Hr style={hr} />

          {/* Footer Content */}
          <Section>
            <Text style={footer}>
              © {new Date().getFullYear()} MPH Inc. All rights reserved.
            </Text>

            <Text style={footerLinks}>
              <Link href="https://mph-app.com" style={link}>
                Visit Website
              </Link>{' '}
              •{' '}
              <Link href="https://mph-app.com/privacy" style={link}>
                Privacy Policy
              </Link>
            </Text>
          </Section>
        </Container>
      </Body>
    </Html>
  )
}

// --- STYLES (MPH Branding + Vercel Minimalism) ---

const main = {
  backgroundColor: '#ffffff',
  fontFamily:
    '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
  margin: '0 auto',
  padding: '20px 0 48px'
}

const container = {
  backgroundColor: '#ffffff',
  border: '1px solid #eaeaea',
  borderRadius: '5px',
  margin: '0 auto',
  padding: '20px',
  maxWidth: '465px',
  width: '100%'
}

const logo = {
  color: '#e20b13', // MPH Brand Red
  fontSize: '24px',
  fontWeight: 'bold',
  textAlign: 'center' as const,
  margin: '0',
  letterSpacing: '-0.5px'
}

const headingStyle = {
  color: '#000000',
  fontSize: '24px',
  fontWeight: '600',
  textAlign: 'center' as const,
  margin: '30px 0'
}

const content = {
  marginTop: '32px'
}

const hr = {
  borderColor: '#eaeaea',
  margin: '26px 0'
}

const footer = {
  color: '#666666',
  fontSize: '12px',
  lineHeight: '24px',
  textAlign: 'center' as const,
  marginBottom: '20px'
}

const footerLinks = {
  textAlign: 'center' as const,
  fontSize: '12px',
  color: '#666666'
}

const link = {
  color: '#666666',
  textDecoration: 'underline'
}
