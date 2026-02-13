import { ARCHITECTURE_LAYERS } from '@/lib/constants'

export default function ArchitectureSection() {
  return (
    <section id="architecture" className="py-24 relative">
      <div className="mx-auto max-w-4xl px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="font-display text-3xl sm:text-4xl font-bold tracking-tight">
            <span className="gradient-text">Architecture</span>
          </h2>
          <p className="mt-4 text-gray-400 max-w-2xl mx-auto">
            Layered, modular design. Each layer depends only on layers below it. No circular dependencies.
          </p>
        </div>

        <div className="flex flex-col gap-3">
          {[...ARCHITECTURE_LAYERS].reverse().map((layer, i) => (
            <div
              key={i}
              className={`group relative rounded-lg p-5 border transition-all duration-300 hover:scale-[1.02] ${
                layer.color === 'cyan'
                  ? 'border-cyber-cyan/20 bg-cyber-cyan/5 hover:border-cyber-cyan/50 hover:shadow-neon-cyan'
                  : 'border-cyber-purple/20 bg-cyber-purple/5 hover:border-cyber-purple/50 hover:shadow-neon-purple'
              }`}
            >
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                <h3 className={`font-mono text-sm font-bold tracking-wide ${
                  layer.color === 'cyan' ? 'text-cyber-cyan' : 'text-cyber-purple'
                }`}>
                  {layer.label}
                </h3>
                <p className="text-xs text-gray-500 font-mono">
                  {layer.description}
                </p>
              </div>

              {/* Connector line */}
              {i < ARCHITECTURE_LAYERS.length - 1 && (
                <div className="absolute -bottom-3 left-1/2 -translate-x-1/2 w-px h-3 bg-gradient-to-b from-cyber-border to-transparent" />
              )}
            </div>
          ))}
        </div>

        {/* Bottom label */}
        <div className="mt-8 text-center">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-cyber-border bg-cyber-surface/50">
            <div className="h-2 w-2 rounded-full bg-cyber-cyan/50" />
            <span className="text-xs font-mono text-gray-500">q-common — shared types, errors, utilities</span>
          </div>
        </div>
      </div>
    </section>
  )
}
