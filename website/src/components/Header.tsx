'use client'

import { useState } from 'react'
import { NAV_LINKS, SITE_CONFIG } from '@/lib/constants'

export default function Header() {
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <header className="fixed inset-x-0 top-0 z-50 border-b border-white/10 bg-[#071022]/80 backdrop-blur-xl">
      <div className="section-wrap">
        <div className="flex h-16 items-center justify-between">
          <a href="#" className="group flex items-center gap-3">
            <div className="relative h-8 w-8 overflow-hidden rounded-md border border-white/20 bg-[#0f1d33]">
              <div className="absolute inset-1 rounded-sm border border-qedge-cyan/50" />
              <div className="absolute left-1/2 top-1/2 h-1 w-1 -translate-x-1/2 -translate-y-1/2 rounded-full bg-qedge-amber" />
            </div>
            <div>
              <p className="font-display text-[0.72rem] uppercase tracking-[0.2em] text-qedge-cyan">Qbitel</p>
              <p className="text-sm font-semibold text-white">EdgeOS</p>
            </div>
          </a>

          <nav className="hidden items-center gap-2 md:flex">
            {NAV_LINKS.map((link) => (
              <a
                key={link.href}
                href={link.href}
                className="rounded-lg px-3 py-2 text-sm text-qedge-muted transition-colors hover:text-white"
              >
                {link.label}
              </a>
            ))}
          </nav>

          <div className="hidden items-center gap-3 md:flex">
            <a href={SITE_CONFIG.github} target="_blank" rel="noopener noreferrer" className="btn-secondary">
              GitHub
            </a>
            <a href="#quickstart" className="btn-primary">
              Launch Quick Start
            </a>
          </div>

          <button
            type="button"
            onClick={() => setMobileOpen((prev) => !prev)}
            className="rounded-lg border border-white/20 p-2 text-qedge-muted md:hidden"
            aria-label="Toggle menu"
          >
            <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              {mobileOpen ? (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              ) : (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
              )}
            </svg>
          </button>
        </div>

        {mobileOpen && (
          <div className="mb-4 rounded-xl border border-white/10 bg-[#0b162b]/95 p-4 md:hidden">
            <nav className="flex flex-col gap-2">
              {NAV_LINKS.map((link) => (
                <a
                  key={link.href}
                  href={link.href}
                  onClick={() => setMobileOpen(false)}
                  className="rounded-md px-3 py-2 text-sm text-qedge-muted hover:bg-white/5 hover:text-white"
                >
                  {link.label}
                </a>
              ))}
              <a href={SITE_CONFIG.github} target="_blank" rel="noopener noreferrer" className="btn-secondary mt-2">
                GitHub
              </a>
              <a href="#quickstart" onClick={() => setMobileOpen(false)} className="btn-primary">
                Launch Quick Start
              </a>
            </nav>
          </div>
        )}
      </div>
    </header>
  )
}
