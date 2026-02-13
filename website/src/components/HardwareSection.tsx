import { HARDWARE_PLATFORMS } from '@/lib/constants'

export default function HardwareSection() {
  return (
    <section id="hardware" className="py-24 relative bg-cyber-surface/30">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="font-display text-3xl sm:text-4xl font-bold tracking-tight">
            <span className="gradient-text">Supported Hardware</span>
          </h2>
          <p className="mt-4 text-gray-400 max-w-2xl mx-auto">
            Runs on real microcontrollers. 512KB flash, 128KB RAM minimum. Hardware TRNG and OTP/eFUSE required.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {HARDWARE_PLATFORMS.map((platform) => (
            <div key={platform.name} className="card-cyber group relative overflow-hidden">
              {/* Status badge */}
              <div className="absolute top-4 right-4">
                <span className={`inline-flex px-2 py-0.5 rounded text-xs font-mono ${
                  platform.status === 'Primary'
                    ? 'bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/20'
                    : 'bg-cyber-yellow/10 text-cyber-yellow border border-cyber-yellow/20'
                }`}>
                  {platform.status}
                </span>
              </div>

              {/* MCU Name */}
              <h3 className="text-xl font-bold text-white mb-1 group-hover:text-cyber-cyan transition-colors">
                {platform.name}
              </h3>
              <p className="text-sm text-cyber-purple font-mono mb-4">{platform.mcu}</p>

              {/* Specs */}
              <div className="space-y-3 mb-4">
                <div className="flex justify-between items-center text-sm">
                  <span className="text-gray-500">Architecture</span>
                  <span className="font-mono text-gray-300">{platform.arch}</span>
                </div>
                <div className="flex justify-between items-center text-sm">
                  <span className="text-gray-500">Flash</span>
                  <span className="font-mono text-cyber-cyan">{platform.flash}</span>
                </div>
                <div className="flex justify-between items-center text-sm">
                  <span className="text-gray-500">RAM</span>
                  <span className="font-mono text-cyber-cyan">{platform.ram}</span>
                </div>
              </div>

              {/* Target Triple */}
              <div className="mt-4 p-2 rounded bg-cyber-bg/80 border border-cyber-border/50">
                <code className="text-xs font-mono text-gray-500 break-all">{platform.target}</code>
              </div>

              {/* Features */}
              <div className="mt-4 flex flex-wrap gap-2">
                {platform.features.map((f) => (
                  <span key={f} className="px-2 py-0.5 rounded text-xs bg-cyber-surface border border-cyber-border text-gray-500">
                    {f}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
