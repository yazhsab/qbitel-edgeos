import type { Metadata } from 'next'
import { Inter, JetBrains_Mono, Orbitron } from 'next/font/google'
import './globals.css'

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-inter',
})

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-jetbrains',
})

const orbitron = Orbitron({
  subsets: ['latin'],
  variable: '--font-orbitron',
})

export const metadata: Metadata = {
  title: 'Qbitel EdgeOS — Post-Quantum Secure OS for Edge Devices',
  description:
    'Open-source embedded operating system with NIST-standardized post-quantum cryptography, hardware-rooted identity, secure boot, and mesh networking. Written in Rust. Designed for critical infrastructure.',
  keywords: [
    'post-quantum cryptography',
    'embedded OS',
    'Rust',
    'no_std',
    'edge computing',
    'ML-KEM',
    'ML-DSA',
    'IoT security',
    'critical infrastructure',
    'mesh networking',
    'secure boot',
    'STM32',
    'RISC-V',
  ],
  authors: [{ name: 'Qbitel Inc.' }],
  openGraph: {
    title: 'Qbitel EdgeOS — Post-Quantum Secure OS for Edge Devices',
    description:
      'NIST-standardized PQC. Hardware-rooted identity. Secure boot. Mesh networking. Written in Rust.',
    url: 'https://yazhsab.github.io/qbitel-edgeos',
    siteName: 'Qbitel EdgeOS',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Qbitel EdgeOS — Post-Quantum Secure OS for Edge Devices',
    description:
      'NIST-standardized PQC. Hardware-rooted identity. Secure boot. Mesh networking. Written in Rust.',
  },
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className={`${inter.variable} ${jetbrainsMono.variable} ${orbitron.variable}`}>
      <body className={`${inter.className} antialiased`}>{children}</body>
    </html>
  )
}
