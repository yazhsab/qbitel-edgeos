import { CRYPTO_ALGORITHMS } from '@/lib/constants'

export default function CryptoSection() {
  return (
    <section id="crypto" className="py-24 relative">
      <div className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="font-display text-3xl sm:text-4xl font-bold tracking-tight">
            <span className="gradient-text">Cryptographic Algorithms</span>
          </h2>
          <p className="mt-4 text-gray-400 max-w-2xl mx-auto">
            NIST-standardized post-quantum cryptography. All operations are constant-time. No secret-dependent branches.
          </p>
        </div>

        {/* Desktop Table */}
        <div className="hidden md:block overflow-hidden rounded-lg border border-cyber-cyan/15">
          <table className="w-full">
            <thead>
              <tr className="bg-cyber-cyan/5 border-b border-cyber-cyan/15">
                <th className="px-6 py-4 text-left text-xs font-mono font-bold text-cyber-cyan uppercase tracking-wider">Algorithm</th>
                <th className="px-6 py-4 text-left text-xs font-mono font-bold text-cyber-cyan uppercase tracking-wider">Standard</th>
                <th className="px-6 py-4 text-left text-xs font-mono font-bold text-cyber-cyan uppercase tracking-wider">Use</th>
                <th className="px-6 py-4 text-left text-xs font-mono font-bold text-cyber-cyan uppercase tracking-wider">Security</th>
                <th className="px-6 py-4 text-left text-xs font-mono font-bold text-cyber-cyan uppercase tracking-wider">Key Size</th>
                <th className="px-6 py-4 text-left text-xs font-mono font-bold text-cyber-cyan uppercase tracking-wider">Output</th>
              </tr>
            </thead>
            <tbody>
              {CRYPTO_ALGORITHMS.map((algo, i) => (
                <tr
                  key={algo.name}
                  className={`border-b border-cyber-border/30 hover:bg-cyber-cyan/5 transition-colors ${
                    i % 2 === 0 ? 'bg-cyber-surface/30' : 'bg-transparent'
                  }`}
                >
                  <td className="px-6 py-4 text-sm font-mono font-semibold text-white">{algo.name}</td>
                  <td className="px-6 py-4 text-sm font-mono text-cyber-purple">{algo.standard}</td>
                  <td className="px-6 py-4 text-sm text-gray-400">{algo.use}</td>
                  <td className="px-6 py-4">
                    <span className={`inline-flex px-2 py-0.5 rounded text-xs font-mono ${
                      algo.level.includes('Level 3')
                        ? 'bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/20'
                        : algo.level.includes('Level 1')
                        ? 'bg-cyber-yellow/10 text-cyber-yellow border border-cyber-yellow/20'
                        : 'bg-cyber-purple/10 text-cyber-purple border border-cyber-purple/20'
                    }`}>
                      {algo.level}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm font-mono text-gray-500">{algo.keySize}</td>
                  <td className="px-6 py-4 text-sm font-mono text-gray-500">{algo.outputSize}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Mobile Cards */}
        <div className="md:hidden space-y-4">
          {CRYPTO_ALGORITHMS.map((algo) => (
            <div key={algo.name} className="card-cyber">
              <h3 className="font-mono text-sm font-bold text-white mb-2">{algo.name}</h3>
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div><span className="text-gray-500">Standard:</span> <span className="text-cyber-purple font-mono">{algo.standard}</span></div>
                <div><span className="text-gray-500">Use:</span> <span className="text-gray-300">{algo.use}</span></div>
                <div><span className="text-gray-500">Security:</span> <span className="text-cyber-cyan font-mono">{algo.level}</span></div>
                <div><span className="text-gray-500">Output:</span> <span className="text-gray-300 font-mono">{algo.outputSize}</span></div>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-8 text-center text-xs text-gray-600 font-mono">
          All secrets automatically zeroized on drop • Integer overflow checks in release builds
        </div>
      </div>
    </section>
  )
}
