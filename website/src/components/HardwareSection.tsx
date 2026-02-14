import { HARDWARE_PLATFORMS } from '@/lib/constants'

export default function HardwareSection() {
  return (
    <section id="hardware" className="py-16 sm:py-20">
      <div className="section-wrap">
        <div className="mb-10 max-w-3xl">
          <span className="eyebrow">Security Architecture</span>
          <h2 className="mt-4 text-3xl font-semibold text-white sm:text-4xl">Hardware-rooted and operationally deterministic.</h2>
          <p className="text-muted mt-4 text-base leading-relaxed">
            The runtime is optimized for constrained edge devices where uptime, timing predictability, and identity trust
            are non-negotiable.
          </p>
        </div>

        <div className="grid gap-5 md:grid-cols-3">
          {HARDWARE_PLATFORMS.map((platform, index) => (
            <article
              key={platform.name}
              className="reveal-up rounded-2xl border border-white/10 bg-[#0b172d]/90 p-6"
              style={{ animationDelay: `${90 + index * 85}ms` }}
            >
              <h3 className="text-xl font-semibold text-white">{platform.name}</h3>
              <p className="text-muted mt-3 text-sm leading-relaxed">{platform.detail}</p>
              <div className="mt-4 flex flex-wrap gap-2">
                {platform.tags.map((tag) => (
                  <span key={tag} className="tech-chip">
                    {tag}
                  </span>
                ))}
              </div>
            </article>
          ))}
        </div>
      </div>
    </section>
  )
}
