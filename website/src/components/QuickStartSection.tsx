import { QUICKSTART_STEPS, SITE_CONFIG } from '@/lib/constants'

export default function QuickStartSection() {
  return (
    <section id="quickstart" className="py-16 sm:py-20">
      <div className="section-wrap">
        <div className="mb-10 max-w-3xl">
          <span className="eyebrow">Quick Start</span>
          <h2 className="mt-4 text-3xl font-semibold text-white sm:text-4xl">From repository clone to secure deployment flow.</h2>
          <p className="text-muted mt-4 text-base leading-relaxed">
            These commands form a practical starting path for build, validation, and device provisioning.
          </p>
        </div>

        <div className="space-y-4">
          {QUICKSTART_STEPS.map((step, index) => (
            <article
              key={step.label}
              className="reveal-up flex items-start gap-4 rounded-2xl border border-white/10 bg-[#0a1527]/85 p-4"
              style={{ animationDelay: `${90 + index * 80}ms` }}
            >
              <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full border border-qedge-cyan/40 bg-qedge-cyan/10 text-sm font-semibold text-qedge-cyan">
                {index + 1}
              </div>
              <div className="w-full">
                <p className="text-sm font-semibold text-white">{step.label}</p>
                <div className="terminal-shell mt-2">
                  <p className="break-all text-qedge-cyan">$ {step.cmd}</p>
                </div>
                <p className="text-muted mt-2 text-xs">{step.note}</p>
              </div>
            </article>
          ))}
        </div>

        <div className="mt-8 flex flex-wrap gap-3">
          <a href={SITE_CONFIG.github} target="_blank" rel="noopener noreferrer" className="btn-primary">
            Repository
          </a>
          <a href={`${SITE_CONFIG.github}/blob/main/docs/DEPLOYMENT.md`} target="_blank" rel="noopener noreferrer" className="btn-secondary">
            Deployment Guide
          </a>
        </div>
      </div>
    </section>
  )
}
