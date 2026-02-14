import { SITE_CONFIG } from '@/lib/constants'

type FooterLink = [string, string]

const footerLinks = {
  framework: [
    ['Architecture', '#architecture'],
    ['Core Crates', '#crates'],
    ['Cryptography', '#crypto'],
  ],
  operations: [
    ['Target Domains', '#usecases'],
    ['Operational Tools', '#tools'],
    ['Quick Start', '#quickstart'],
  ],
  resources: [
    ['GitHub', SITE_CONFIG.github],
    ['Issues', `${SITE_CONFIG.github}/issues`],
    ['License', `${SITE_CONFIG.github}/blob/main/LICENSE`],
  ],
} satisfies Record<'framework' | 'operations' | 'resources', FooterLink[]>

export default function Footer() {
  return (
    <footer className="border-t border-white/10 bg-[#050d1a]">
      <div className="section-wrap py-12">
        <div className="grid gap-8 md:grid-cols-2 lg:grid-cols-4">
          <div>
            <p className="font-display text-xs uppercase tracking-[0.2em] text-qedge-cyan">Qbitel</p>
            <h3 className="mt-1 text-2xl font-semibold text-white">EdgeOS</h3>
            <p className="text-muted mt-3 text-sm leading-relaxed">{SITE_CONFIG.tagline}</p>
            <div className="mt-4 flex flex-wrap gap-2">
              <span className="tech-chip">v{SITE_CONFIG.version}</span>
              <span className="tech-chip">Apache-2.0</span>
            </div>
          </div>

          <FooterColumn title="Framework" links={footerLinks.framework} />
          <FooterColumn title="Operations" links={footerLinks.operations} />
          <FooterColumn title="Resources" links={footerLinks.resources} external />
        </div>

        <div className="mt-10 border-t border-white/10 pt-6 text-xs text-qedge-muted">
          <p>Built for long-lifecycle critical infrastructure systems facing post-quantum transition requirements.</p>
          <p className="mt-1">© {new Date().getFullYear()} Qbitel Inc. All rights reserved.</p>
        </div>
      </div>
    </footer>
  )
}

function FooterColumn({
  title,
  links,
  external,
}: {
  title: string
  links: FooterLink[]
  external?: boolean
}) {
  return (
    <div>
      <h4 className="font-mono text-xs uppercase tracking-[0.14em] text-qedge-cyan">{title}</h4>
      <ul className="mt-3 space-y-2">
        {links.map(([label, href]) => (
          <li key={label}>
            <a
              href={href}
              target={external ? '_blank' : undefined}
              rel={external ? 'noopener noreferrer' : undefined}
              className="text-sm text-qedge-muted transition-colors hover:text-white"
            >
              {label}
            </a>
          </li>
        ))}
      </ul>
    </div>
  )
}
