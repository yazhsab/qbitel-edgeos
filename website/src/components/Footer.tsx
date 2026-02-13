import { SITE_CONFIG } from '@/lib/constants'

export default function Footer() {
  return (
    <footer className="border-t border-cyber-border/50 bg-cyber-bg">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-8">
          {/* Brand */}
          <div>
            <div className="flex items-center gap-2 mb-4">
              <div className="h-8 w-8 rounded-md bg-gradient-to-br from-cyber-cyan/20 to-cyber-purple/20 border border-cyber-cyan/30 flex items-center justify-center">
                <span className="font-display text-xs font-bold text-cyber-cyan">Q</span>
              </div>
              <span className="font-display text-sm font-semibold tracking-wider text-white">
                QBITEL <span className="text-cyber-cyan">EDGE</span>OS
              </span>
            </div>
            <p className="text-sm text-gray-500 leading-relaxed">
              Post-quantum secure embedded OS for critical infrastructure. Built with Rust.
            </p>
            <div className="mt-4 flex items-center gap-2">
              <span className="inline-flex items-center px-2 py-1 rounded text-xs font-mono bg-cyber-surface border border-cyber-border text-gray-400">
                v{SITE_CONFIG.version}
              </span>
              <span className="inline-flex items-center px-2 py-1 rounded text-xs font-mono bg-cyber-surface border border-cyber-border text-gray-400">
                Apache-2.0
              </span>
            </div>
          </div>

          {/* Documentation */}
          <div>
            <h3 className="text-sm font-semibold text-white mb-4 tracking-wide uppercase">Documentation</h3>
            <ul className="space-y-2">
              {[
                ['Product Overview', `${SITE_CONFIG.github}/blob/main/docs/PRODUCT_OVERVIEW.md`],
                ['Quick Start', `${SITE_CONFIG.github}/blob/main/docs/QUICKSTART.md`],
                ['API Reference', `${SITE_CONFIG.github}/blob/main/docs/API.md`],
                ['Deployment Guide', `${SITE_CONFIG.github}/blob/main/docs/DEPLOYMENT.md`],
              ].map(([label, href]) => (
                <li key={label}>
                  <a href={href} target="_blank" rel="noopener noreferrer" className="text-sm text-gray-500 hover:text-cyber-cyan transition-colors">
                    {label}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Community */}
          <div>
            <h3 className="text-sm font-semibold text-white mb-4 tracking-wide uppercase">Community</h3>
            <ul className="space-y-2">
              {[
                ['GitHub', SITE_CONFIG.github],
                ['Issues', `${SITE_CONFIG.github}/issues`],
                ['Discussions', `${SITE_CONFIG.github}/discussions`],
                ['Contributing', `${SITE_CONFIG.github}/blob/main/CONTRIBUTING.md`],
              ].map(([label, href]) => (
                <li key={label}>
                  <a href={href} target="_blank" rel="noopener noreferrer" className="text-sm text-gray-500 hover:text-cyber-cyan transition-colors">
                    {label}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Security */}
          <div>
            <h3 className="text-sm font-semibold text-white mb-4 tracking-wide uppercase">Security</h3>
            <ul className="space-y-2">
              {[
                ['Security Policy', `${SITE_CONFIG.github}/blob/main/SECURITY.md`],
                ['Code of Conduct', `${SITE_CONFIG.github}/blob/main/CODE_OF_CONDUCT.md`],
                ['License', `${SITE_CONFIG.github}/blob/main/LICENSE`],
              ].map(([label, href]) => (
                <li key={label}>
                  <a href={href} target="_blank" rel="noopener noreferrer" className="text-sm text-gray-500 hover:text-cyber-cyan transition-colors">
                    {label}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        </div>

        <div className="mt-12 pt-8 border-t border-cyber-border/30 text-center">
          <p className="text-xs text-gray-600">
            Built with Rust. Secured with post-quantum cryptography. Designed for critical infrastructure.
          </p>
          <p className="text-xs text-gray-700 mt-1">
            &copy; {new Date().getFullYear()} Qbitel Inc. All rights reserved.
          </p>
        </div>
      </div>
    </footer>
  )
}
