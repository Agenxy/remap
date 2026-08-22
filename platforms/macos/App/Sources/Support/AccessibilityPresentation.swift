import SwiftUI

struct AccessibilityPresentation: Equatable {
    let reduceMotion: Bool
    let increasedContrast: Bool
    let differentiateWithoutColor: Bool

    var statusFillOpacity: Double {
        increasedContrast ? 0.18 : 0.1
    }

    var statusBorderOpacity: Double {
        if increasedContrast {
            return 0.9
        }
        return differentiateWithoutColor ? 0.65 : 0.35
    }

    var statusBorderWidth: CGFloat {
        increasedContrast || differentiateWithoutColor ? 2 : 1
    }

    var disablesMotion: Bool {
        reduceMotion
    }
}

struct AccessibleMotion: ViewModifier {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func body(content: Content) -> some View {
        content.transaction { transaction in
            if reduceMotion {
                transaction.animation = nil
            }
        }
    }
}

extension View {
    func respectsReducedMotion() -> some View {
        modifier(AccessibleMotion())
    }
}
