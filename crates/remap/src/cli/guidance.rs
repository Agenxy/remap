// SPDX-License-Identifier: GPL-3.0-or-later
//! Long help text for the commands defined in `cli.rs`.

pub(super) const DOCTOR_GUIDANCE: &str = concat!(
    "Checks:\n",
    "  authority identity and registry status\n",
    "  authenticated UDP and TCP DNS listeners\n",
    "  authenticated HTTP gateway\n",
    "  whether upstream DNS resolvers still answer forwarded names\n\n",
    "Doctor never changes system state. A collected report exits successfully even when a\n",
    "component is unavailable; automation should inspect the JSON readiness fields.\n\n",
    "Examples:\n",
    "  remap doctor\n",
    "  remap --json doctor",
);
pub(super) const SET_GUIDANCE: &str = concat!(
    "Examples:\n",
    "  remap set remap.test http://127.0.0.1:4270\n",
    "  remap set '*.lab' https://example.com:9443 --host-header use-upstream\n",
    "  remap set atlas 127.0.0.1 --expect 12 --operation-id <UUID>\n",
    "  remap set pro.internal 'supgang://<node-id>?ssh=22,k7=7443'\n\n",
    "A supgang://<node-id>?<service>=<port> target names a Supgang peer machine by its node ID\n",
    "(64 lowercase hex) or fingerprint (8), never its name. Its name answers one loopback\n",
    "address in 127.77.0.0/16, and each listed port is carried through Supgang to the service\n",
    "the peer's owner exposes with 'supgang expose'. TCP only; UDP and unexposed services are\n",
    "not reachable. Every listed port is reachable from anything on this Mac that can open a\n",
    "loopback TCP connection, so list only services the peer protects itself, such as ssh.\n",
    "The name answers only while Remap holds every listed port. On macOS the installed helper\n",
    "creates the sockets, so ssh=22 works; on Linux ports below 1024 need\n",
    "CAP_NET_BIND_SERVICE, and a port another service holds on every address cannot be held.\n\n",
    "Without explicit guards, Remap reads the current revision and creates an operation ID.\n",
    "If the response is lost after submission, the diagnostic preserves both values so the\n",
    "state can be inspected and the identical operation retried safely.",
);
pub(super) const TOP_LEVEL_EXAMPLES: &str = concat!(
    "Examples:\n",
    "  remap validate atlas http://127.0.0.1:5173\n",
    "  remap list --all\n",
    "  remap set remap.test http://127.0.0.1:5173\n",
    "  remap doctor\n",
    "  remap daemon\n",
    "  remap mcp\n\n",
    "Names may be bare or dotted; .test is reserved for private testing.\n",
    "An installed Remap service owns the authority automatically.\n",
    "Use 'remap daemon' only for an explicit foreground development instance.\n",
    "Use --json for automation.",
);
