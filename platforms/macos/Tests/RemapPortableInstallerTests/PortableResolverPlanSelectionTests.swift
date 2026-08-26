@testable import RemapPortableInstaller
import RemapSystemKit
import Testing

@Test(arguments: [ActivationPhase?.none, .some(.prepared)])
func portablePreparationUsesLiveDNSUnlessRemapIsActive(phase: ActivationPhase?) {
    #expect(PortableResolverPlanSelection(phase: phase) == .ordinary)
}

@Test
func portablePreparationReconcilesAnActiveRemapResolver() {
    #expect(PortableResolverPlanSelection(phase: .active) == .activation)
}
