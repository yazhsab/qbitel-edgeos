import { CRYPTO_ALGORITHMS } from '@/lib/constants'

export default function CryptoSection() {
  return (
    <section id="crypto" className="py-16 sm:py-20">
      <div className="section-wrap">
        <div className="mb-10 max-w-3xl">
          <span className="eyebrow">Native Cryptography</span>
          <h2 className="mt-4 text-3xl font-semibold text-white sm:text-4xl">PQC is built in, not bolted on.</h2>
          <p className="text-muted mt-4 text-base leading-relaxed">
            Algorithms are integrated into the runtime core for deterministic, constant-time operations on constrained
            microcontroller targets.
          </p>
        </div>

        <div className="hidden overflow-hidden rounded-2xl border border-white/10 bg-[#091426]/90 md:block">
          <table className="w-full">
            <thead>
              <tr className="border-b border-white/10 bg-white/[0.02] text-left">
                <th className="px-5 py-4 font-mono text-xs uppercase tracking-[0.16em] text-qedge-cyan">Algorithm</th>
                <th className="px-5 py-4 font-mono text-xs uppercase tracking-[0.16em] text-qedge-cyan">Standard</th>
                <th className="px-5 py-4 font-mono text-xs uppercase tracking-[0.16em] text-qedge-cyan">Purpose</th>
                <th className="px-5 py-4 font-mono text-xs uppercase tracking-[0.16em] text-qedge-cyan">Security</th>
                <th className="px-5 py-4 font-mono text-xs uppercase tracking-[0.16em] text-qedge-cyan">Performance</th>
              </tr>
            </thead>
            <tbody>
              {CRYPTO_ALGORITHMS.map((algo) => (
                <tr key={algo.name} className="border-b border-white/5 hover:bg-white/[0.02]">
                  <td className="px-5 py-4 font-mono text-sm text-white">{algo.name}</td>
                  <td className="px-5 py-4 text-sm text-qedge-amber">{algo.standard}</td>
                  <td className="px-5 py-4 text-sm text-qedge-ink/90">{algo.purpose}</td>
                  <td className="px-5 py-4 text-sm text-qedge-cyan">{algo.level}</td>
                  <td className="px-5 py-4 text-sm text-qedge-muted">{algo.perf}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="space-y-3 md:hidden">
          {CRYPTO_ALGORITHMS.map((algo) => (
            <article key={algo.name} className="surface-panel p-4">
              <p className="font-mono text-sm text-qedge-cyan">{algo.name}</p>
              <p className="mt-2 text-sm text-white">{algo.purpose}</p>
              <div className="mt-3 flex flex-wrap gap-2">
                <span className="tech-chip">{algo.standard}</span>
                <span className="tech-chip">{algo.level}</span>
                <span className="tech-chip">{algo.perf}</span>
              </div>
            </article>
          ))}
        </div>
      </div>
    </section>
  )
}
