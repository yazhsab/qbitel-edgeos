import { WHY_ITEMS } from '@/lib/constants'

export default function WhySection() {
  return (
    <section id="why" className="py-16 sm:py-20">
      <div className="section-wrap">
        <div className="mb-10 max-w-3xl">
          <span className="eyebrow">Quantum Threat Outlook</span>
          <h2 className="mt-4 text-3xl font-semibold text-white sm:text-4xl">
            Legacy cryptography timelines and infrastructure timelines no longer match.
          </h2>
          <p className="text-muted mt-4 text-base leading-relaxed">
            The security gap is not hypothetical. It is a lifecycle mismatch between deployed devices and rapidly evolving
            decryption capability.
          </p>
        </div>

        <div className="grid gap-5 md:grid-cols-3">
          {WHY_ITEMS.map((item, index) => (
            <article
              key={item.title}
              className="surface-panel reveal-up p-6"
              style={{ animationDelay: `${120 + index * 90}ms` }}
            >
              <p className="font-mono text-xs uppercase tracking-[0.16em] text-qedge-cyan">{item.metric}</p>
              <h3 className="mt-3 text-xl font-semibold text-white">{item.title}</h3>
              <p className="text-muted mt-3 text-sm leading-relaxed">{item.description}</p>
            </article>
          ))}
        </div>
      </div>
    </section>
  )
}
