import { TOOLS } from '@/lib/constants'

export default function ToolsSection() {
  return (
    <section id="tools" className="py-16 sm:py-20">
      <div className="section-wrap">
        <div className="mb-10 max-w-3xl">
          <span className="eyebrow">Operational Tools</span>
          <h2 className="mt-4 text-3xl font-semibold text-white sm:text-4xl">Signing and provisioning pipelines for secure fleets.</h2>
          <p className="text-muted mt-4 text-base leading-relaxed">
            Tooling is designed for manufacturing lines, controlled environments, and field operations where policy and
            auditability are first-class requirements.
          </p>
        </div>

        <div className="grid gap-5 lg:grid-cols-2">
          {TOOLS.map((tool, index) => (
            <article
              key={tool.name}
              className="reveal-up surface-panel p-6"
              style={{ animationDelay: `${100 + index * 120}ms` }}
            >
              <div className="mb-3 flex items-center justify-between gap-4">
                <h3 className="font-mono text-lg text-qedge-cyan">{tool.name}</h3>
                <span className="rounded-full border border-qedge-amber/40 bg-qedge-amber/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.12em] text-qedge-amber">
                  Python CLI
                </span>
              </div>
              <p className="text-muted mb-4 text-sm leading-relaxed">{tool.description}</p>

              <div className="terminal-shell space-y-3">
                {tool.commands.map((command) => (
                  <div key={command.cmd}>
                    <p className="text-[11px] uppercase tracking-[0.14em] text-qedge-muted">{command.label}</p>
                    <p className="mt-1 break-all text-qedge-cyan">$ {command.cmd}</p>
                  </div>
                ))}
              </div>
            </article>
          ))}
        </div>
      </div>
    </section>
  )
}
