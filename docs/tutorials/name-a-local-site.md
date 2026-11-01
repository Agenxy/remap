# Name a local site

Replace `YOUR-SUFFIX` in these examples with the suffix you choose. Remap does
not require a product namespace. Start with a site listening on a local port.

## Map the origin root

```text
remap set site.YOUR-SUFFIX http://127.0.0.1:8792/
remap get site.YOUR-SUFFIX
```

Requests for `/bar.css` now reach `/bar.css` at that origin. A target such as
`http://127.0.0.1:8792/page/` deliberately prefixes every request with `/page/`.
Remap warns about that behavior and still honors it.

## Open one page by default

```text
remap set score.YOUR-SUFFIX http://127.0.0.1:8792/ --landing /ops/scorecard/
remap validate score.YOUR-SUFFIX http://127.0.0.1:8792/ --landing /ops/scorecard/
```

Opening the root redirects to the scorecard on the same name. Its query stays
intact. Assets, other pages and POST requests keep their original paths. Landing
also works with a Supgang service target. It requires an origin-root HTTP target
when a normal HTTP URL is used.

## Choose a wildcard and host policy

```text
remap set '*.YOUR-SUFFIX' http://127.0.0.1:8792/
remap set '*.YOUR-SUFFIX' http://127.0.0.1:8792/ --host-header preserve-client
```

Use-upstream is the default. It sends the configured upstream host, which works
with development servers that reject unknown Host values. Choose preserve-client
when the origin intentionally serves multiple names or selects virtual hosts by
the requested name. Configure those names at the origin too. Remap gives an
advisory hint when several names share an origin under use-upstream; it never
changes that policy silently.

## Rename a name safely

First map the new name to its real service, then redirect the old one:

```text
remap set new.YOUR-SUFFIX http://127.0.0.1:8792/
remap set old.YOUR-SUFFIX --moved-to new.YOUR-SUFFIX --until 2030-01-01T00:00:00Z
remap list
```

Every request for the old name receives a 301 to the new name with its original
path and query. At the optional RFC3339 deadline, the old mapping stops matching.
It remains listed until you remove it. A moved name cannot point at itself or
another moved mapping. Removing `--until` creates a redirect without an expiry.

Use preview/apply JSON documents with explicit revision and operation guards
when several changes must be atomic. Moved targets have the canonical form
`moved://new.YOUR-SUFFIX?until=2030-01-01T00:00:00Z` in those documents and in
machine-readable mapping results.
