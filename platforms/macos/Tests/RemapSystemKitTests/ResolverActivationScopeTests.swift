// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
@testable import RemapSystemKit
import Testing

// ADR-0036. Activation, which every install and update runs, picks its one
// service by the rule supervision follows: the only service with DNS, or the
// one macOS's global resolver uses. On 9 November the owner's Mac had Wi-Fi
// and a USB-C LAN on one office network, each with its own DHCP resolvers,
// and activation refused both as split DNS.

private let wifi = "wifi"
private let lan = "usb-c-lan"

private func service(_ serviceID: String, _ servers: [String]?) -> ObservedNetworkService {
    ObservedNetworkService(
        serviceID: serviceID,
        configuration: nil,
        enabled: true,
        effectiveServers: servers,
        dhcpServers: servers ?? [],
        networkSignature: nil
    )
}

@Test
func theOnlyServiceWithDNSIsActivated() throws {
    let snapshot = NetworkSnapshot(
        services: [service(wifi, ["192.0.2.1"]), service(lan, nil)],
        globalServers: ["192.0.2.1"],
        primaryServiceID: wifi
    )
    #expect(try activationServiceID(usable: [wifi], snapshot: snapshot) == wifi)
}

@Test
func wifiAndAWiredLANOnOneNetworkActivateTheServiceMacOSUses() throws {
    let snapshot = NetworkSnapshot(
        services: [service(wifi, ["17.7.7.207", "17.8.8.208"]), service(lan, ["17.7.7.7", "17.8.8.8"])],
        globalServers: ["17.7.7.7", "17.8.8.8"],
        primaryServiceID: lan
    )
    #expect(try activationServiceID(usable: [wifi, lan], snapshot: snapshot) == lan)
}

@Test
func servicesOnTheSameResolversActivateTheOneMacOSRanksPrimary() throws {
    let snapshot = NetworkSnapshot(
        services: [service(wifi, ["192.0.2.1"]), service(lan, ["192.0.2.1"])],
        globalServers: ["192.0.2.1"],
        primaryServiceID: wifi
    )
    #expect(try activationServiceID(usable: [lan, wifi], snapshot: snapshot) == wifi)
}

@Test
func servicesTheGlobalResolverCannotTellApartAreStillRefused() throws {
    let snapshot = NetworkSnapshot(
        services: [service(wifi, ["192.0.2.1"]), service(lan, ["198.51.100.1"])],
        globalServers: ["203.0.113.9"],
        primaryServiceID: lan
    )
    #expect(throws: ResolverError.unsupportedResolverScope(2)) {
        try activationServiceID(usable: [wifi, lan], snapshot: snapshot)
    }
}

@Test
func aGlobalResolverOnAServiceWithoutUsableDNSIsRefused() throws {
    // The global resolver names a service that is not among the usable ones,
    // so activation cannot configure it and writes nothing.
    let snapshot = NetworkSnapshot(
        services: [service(wifi, ["192.0.2.1"]), service(lan, ["198.51.100.1"]), service("vpn", ["10.0.0.1"])],
        globalServers: ["10.0.0.1"],
        primaryServiceID: "vpn"
    )
    #expect(throws: ResolverError.unsupportedResolverScope(2)) {
        try activationServiceID(usable: [wifi, lan], snapshot: snapshot)
    }
}
