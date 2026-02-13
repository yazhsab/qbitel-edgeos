import Header from '@/components/Header'
import Footer from '@/components/Footer'
import HeroSection from '@/components/HeroSection'
import WhySection from '@/components/WhySection'
import ArchitectureSection from '@/components/ArchitectureSection'
import CratesSection from '@/components/CratesSection'
import CryptoSection from '@/components/CryptoSection'
import HardwareSection from '@/components/HardwareSection'
import UseCasesSection from '@/components/UseCasesSection'
import ExamplesSection from '@/components/ExamplesSection'
import ToolsSection from '@/components/ToolsSection'
import QuickStartSection from '@/components/QuickStartSection'
import ComplianceSection from '@/components/ComplianceSection'

export default function Home() {
  return (
    <>
      <Header />
      <main>
        <HeroSection />
        <WhySection />
        <ArchitectureSection />
        <CratesSection />
        <CryptoSection />
        <HardwareSection />
        <UseCasesSection />
        <ExamplesSection />
        <ToolsSection />
        <QuickStartSection />
        <ComplianceSection />
      </main>
      <Footer />
    </>
  )
}
