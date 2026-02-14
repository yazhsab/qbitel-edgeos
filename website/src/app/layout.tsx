import type { Metadata } from 'next'
import './globals.css'

const basePath = process.env.NODE_ENV === 'production' ? '/qbitel-edgeos' : ''

export const metadata: Metadata = {
  title: 'Qbitel EdgeOS | Post-Quantum Critical Infrastructure Runtime',
  description:
    'Qbitel EdgeOS is a Rust-based, post-quantum secure operating system with hardware-rooted identity, certificate-less trust, and deterministic edge performance.',
  keywords: [
    'Qbitel EdgeOS',
    'post-quantum cryptography',
    'ML-KEM-768',
    'ML-DSA-65',
    'critical infrastructure security',
    'hardware-rooted identity',
    'Rust embedded OS',
  ],
  authors: [{ name: 'Qbitel Inc.' }],
  icons: {
    icon: `${basePath}/favicon.ico`,
  },
  openGraph: {
    title: 'Qbitel EdgeOS | Post-Quantum Critical Infrastructure Runtime',
    description:
      'Built for energy, rail, utilities, and defense systems requiring deterministic performance and cryptographic agility.',
    url: 'https://yazhsab.github.io/qbitel-edgeos',
    siteName: 'Qbitel EdgeOS',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Qbitel EdgeOS | Post-Quantum Critical Infrastructure Runtime',
    description:
      'Rust no-heap architecture, native PQC, and hardware-bound identity for long-lifecycle edge systems.',
  },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  )
}
