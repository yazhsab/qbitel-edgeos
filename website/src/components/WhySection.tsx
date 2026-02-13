import { WHY_ITEMS } from '@/lib/constants'

export default function WhySection() {
  return (
    <section id="why" className="py-24 relative">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="font-display text-3xl sm:text-4xl font-bold tracking-tight">
            <span className="gradient-text">Why Qbitel EdgeOS?</span>
          </h2>
          <p className="mt-4 text-gray-400 max-w-2xl mx-auto">
            The quantum threat to embedded systems is a timeline problem. Devices deployed today must survive threats that arrive tomorrow.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {WHY_ITEMS.map((item, i) => (
            <div key={i} className="card-cyber group">
              <div className="text-3xl mb-4">{item.icon}</div>
              <h3 className="text-lg font-semibold text-white mb-2 group-hover:text-cyber-cyan transition-colors">
                {item.title}
              </h3>
              <p className="text-sm text-gray-400 leading-relaxed">
                {item.description}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
