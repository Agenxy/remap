import Foundation
import Observation
import RemapControlKit

@MainActor
@Observable
final class AppPresentation {
    struct MappingEditor: Identifiable {
        // The short property name is required by Identifiable.
        // swiftlint:disable:next identifier_name
        let id = UUID()
        let original: RemapMapping?
    }

    struct OperationReview: Identifiable {
        // The short property name is required by Identifiable.
        // swiftlint:disable:next identifier_name
        let id = UUID()
        let title: String
        let change: RemapChange
    }

    var mappingEditor: MappingEditor?
    var operationReview: OperationReview?
    var selectedSection = AppSection.overview

    func createMapping() {
        mappingEditor = MappingEditor(original: nil)
    }

    func edit(_ mapping: RemapMapping) {
        mappingEditor = MappingEditor(original: mapping)
    }

    func review(title: String, change: RemapChange) {
        operationReview = OperationReview(title: title, change: change)
    }

    func navigate(to section: AppSection) {
        selectedSection = section
    }
}
