import { TOOLS } from '@/lib/constants'

export default function ToolsSection() {
  return (
    <section id="tools" className="py-24 relative">
      <div className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="font-display text-3xl sm:text-4xl font-bold tracking-tight">
            <span className="gradient-text">Developer Tools</span>
          </h2>
          <p className="mt-4 text-gray-400 max-w-2xl mx-auto">
            Python CLI tools for firmware signing and device provisioning. Install with pip.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {TOOLS.map((tool) => (
            <div key={tool.name} className="card-cyber">
              <div className="flex items-center gap-3 mb-3">
                <span className="text-cyber-purple font-mono text-lg font-bold">{tool.name}</span>
                <span className="px-2 py-0.5 rounded text-xs bg-cyber-surface border border-cyber-border text-gray-500">Python</span>
              </div>
              <p className="text-sm text-gray-400 mb-4">{tool.description}</p>

              <div className="terminal-block">
                <div className="terminal-header">
                  <div className="terminal-dot bg-cyber-red/80" />
                  <div className="terminal-dot bg-cyber-yellow/80" />
                  <div className="terminal-dot bg-cyber-green/80" />
                  <span className="ml-2 text-xs text-gray-600 font-mono">{tool.name}</span>
                </div>
                <div className="p-4 space-y-3">
                  {tool.commands.map((cmd, i) => (
                    <div key={i}>
                      <div className="text-xs text-gray-600 mb-1">
                        <span className="text-gray-700"># {cmd.label}</span>
                      </div>
                      <div className="flex gap-2">
                        <span className="text-cyber-cyan select-none">$</span>
                        <code className="text-cyber-green text-xs break-all">{cmd.cmd}</code>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
