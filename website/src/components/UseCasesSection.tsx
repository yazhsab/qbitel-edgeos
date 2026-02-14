import { USE_CASES } from '@/lib/constants'

export default function UseCasesSection() {
  return (
    <section id="usecases" className="py-16 sm:py-20">
      <div className="section-wrap">
        <div className="mb-10 max-w-3xl">
          <span className="eyebrow">Target Domains</span>
          <h2 className="mt-4 text-3xl font-semibold text-white sm:text-4xl">Built for systems society depends on.</h2>
          <p className="text-muted mt-4 text-base leading-relaxed">
            Qbitel EdgeOS is tailored for critical infrastructure categories where cryptographic failure directly affects
            safety, continuity, and national resilience.
          </p>
        </div>

        <div className="grid gap-5 lg:grid-cols-2">
          {USE_CASES.map((useCase, index) => (
            <article
              key={useCase.title}
              className="reveal-up surface-panel p-6"
              style={{ animationDelay: `${100 + index * 70}ms` }}
            >
              <h3 className="text-xl font-semibold text-white">{useCase.title}</h3>
              <p className="text-muted mt-3 text-sm leading-relaxed">{useCase.description}</p>
              <div className="mt-4 flex flex-wrap gap-2">
                {useCase.systems.map((system) => (
                  <span key={system} className="rounded-md border border-qedge-cyan/25 bg-qedge-cyan/10 px-2.5 py-1 text-xs text-qedge-cyan">
                    {system}
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
