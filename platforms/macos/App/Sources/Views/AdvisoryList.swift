// SPDX-License-Identifier: GPL-3.0-or-later
import SwiftUI

struct AdvisoryList: View {
    let warnings: [String]

    var body: some View {
        if !warnings.isEmpty {
            VStack(alignment: .leading, spacing: 8) {
                Label(AppText.localized("Advisory"), systemImage: "info.circle")
                    .font(.headline)
                    .accessibilityAddTraits(.isHeader)
                ForEach(Array(warnings.enumerated()), id: \.offset) { _, warning in
                    Text(verbatim: warning)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .accessibilityElement(children: .contain)
        }
    }
}
