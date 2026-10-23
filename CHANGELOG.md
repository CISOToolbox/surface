# Changelog

Every release has its section here, written at release time from the
changes since the previous one and published as the GitHub release notes.

## 1.7.1 — 2026-10-23

### Fixed

- A composed character is dispatched once in the Firefox and Safari event order too (socle)
- A character composed with a dead key or an IME is dispatched once, complete (socle)

### Maintenance

- Socle composition dedup (propagation)

## 1.7.0 — 2026-10-20

### Added

- The AI assistant toggle and the module's AI provider in one section, fields usable once the assistant is on (settings)
- One Save button for every section, sections in an exclusive accordion, unsaved changes guarded (settings)
- Settings sections join the shared panel — one Save button, the shared accordion
- Remove a provider's saved keys from the settings drawer (ai)
- The settings drawer lets a standalone module's admin set its AI provider, model and keys (ai)
- A standalone module runs its AI on its server, set by its admin; Pilot's in the suite (ai)
- The local account is shown fixed; without an identity provider the section says the module has one account (users)
- The module's key opens one local account, its admin; other accounts come from an identity provider (auth)
- One shared sign-in router for the nine backend modules — identity providers everywhere (auth)
- Users section in the settings of the backend modules (settings)
- User administration router for standalone modules — module roles, pending, disabled, last admin kept (users)
- Standalone accounts await approval, and their role is read from the module on every request (auth)
- Outbound proxy section in the settings of the backend modules (settings)
- The outbound proxy is settable in the module itself when Pilot is absent (proxy)
- SMTP settings in the standalone modules (shared)

### Fixed

- No multi-tenant Entra default — an unset tenant is empty, and the README says it is required (auth)
- A module menu opened before the module learns it is standalone is closed (chrome)
- A standalone module lists only itself in the module switcher (chrome)
- A given-up section drops its error; AI provider input typed while the assistant is off is discarded (settings)
- Restoring the Nuclei defaults is saved by Save; a cancelled Shodan key leaves nothing pending
- Every way out of the panel asks before unsaved edits go; one save at a time; a refused or declined change stays pending (settings)
- The module honours ALLOW_INSECURE_CUSTOM_LLM_ENDPOINT at call and at save (ai)
- AI settings are stored as they were checked (ai)
- Pilot's push is stored as Pilot checked it; a module admin's endpoint is checked as the call checks it; keys in clear without ENCRYPTION_KEY (ai)
- One email_verified rule for Google and OIDC; tests for OIDC and the account lock (auth)
- An address the identity provider has not verified is refused (auth)
- Only the key's own account is local; the key never revives an account; account creation serialised (auth)
- A provider sign-in marks the account as the provider's; the token closes once such an admin exists (auth)
- A role change says what changed to the module's write journal (users)
- The shared token closes once an admin signs in through the identity provider (auth)
- The last-admin guard locks the admin rows; one journal entry per change (users)
- With an identity provider configured, the shared token only creates the first account (auth)
- A refused sign-in says why — awaiting approval, disabled, domain not allowed (login)
- AppSec, Surface, Watch and Audit sign-in pages show their own name (login)
- Exact masking docstring; contract checks proxy_common never forces allow_private (proxy)
- Mask a token user name with an empty password, redact credentials in any case, contract reads the validator's AST (proxy)
- Mask a token-only proxy userinfo, keep credentials out of refusals, leave omitted fields as they are (proxy)
- The settings router reads proxy_common at call time (proxy)
- SMTP credentials from the environment never go to a host saved in the app (shared)
- SMTP host checked with ssrf_guard; an empty host clears the saved config (shared)
- SMTP settings help says what an empty host really does (shared)
- Honour hideAI in the managed settings drawer (shared)

### Changed

- The region check at save reuses _safe_bedrock_region (ai)
- One proxy URL validator in proxy_common, shared by the internal routes and Pilot (proxy)

### Documentation

- What the shared token allows, translated refusals in the users section (users)

### Tests

- Every proxy_common copy, Pilot's included, passes allow_private on to ssrf_guard (contracts)

## 1.6.0 — 2026-10-15

### Added

- Redirect policy in the target dialog
- The page scanners follow the home page's redirects, validating each hop
- Export_proxy, for a proxy kept outside the proxy.* rows (Pilot's own) (shared)
- Typosquatting settings in the asset dialog, shown with typosquatting only
- Distinguish "not assessed" from 0 in the criticality formula
- Stop the lookalike watch when crt.sh keeps failing
- Alert on certificates issued for typosquatting lookalikes
- Let a scanner chain on another one's findings
- Refresh the AI model catalogue (ai)

### Fixed

- Ct_logs names the lookalikes whose certificates it could not check
- Js_analysis counts only the scripts it fetches, checks a refused host once and keeps what it read
- The scanners that only ask about a name run on one without an address
- Proxy failures are tracked per origin, alternative schemes grouped
- Js_analysis resolves each script host once and keeps the address with its client
- Js_analysis matches script hosts on the normalized target, an IP target reads its own scripts only
- Js_analysis resolves relative scripts against the name and reaches each script host on its own
- A pinned request sends the name as SNI, and Host with a non-default port
- Js_analysis handles its scripts as before, only its root follows target_url
- A gateway error of the proxy on plain HTTP does not count as the target answering
- Js_analysis fetches the scripts by name again, with their TLS name
- The raw-socket proxy warning resolves the target only when a proxy is set
- Directly every js_analysis script is fetched on the address its guard validated
- Js_analysis skips a malformed script URL alone, and reads an IPv6 target's scripts
- Js_analysis keeps a target script's port and params on the locked IP
- An IPv6 target URL is bracketed, and every scanner reads the proxy exceptions the same way
- Js_analysis resolves relative scripts against the target's name
- Chromium's proxy exceptions drop the port, as the other scanners do
- A proxy exception written .domain or *.domain keeps the scanners on the locked IP
- A proxy silent or hanging up on the CONNECT is the proxy's, a failed tunnel the target's
- Chromium gets the proxy of the captured scheme or none, and the proxy exceptions
- Every scanner request error is logged, and inside the https tunnel it is the target's
- Through the proxy the HTTP scanners ask for the scanned name
- Proxy exceptions match the resolved address of takeover and raw-socket targets, the unused HTTP probe goes
- The custom LLM endpoint check follows the proxy, Watch's assistant reaches the custom LLM
- The proxy credentials are masked whatever the password holds
- The AI agent reaches a custom LLM through the outbound proxy
- Nuclei's logged output hides the proxy credentials
- Status line errors are styled and stay long enough to read
- Nuclei's template update output goes to the logs only, stdout included
- Pilot's proxy exempts every registry host once normalized, never '*' or a list, and the default modules even when the database is not ready
- A target some client reached is no proxy failure, across clients; the dispatcher logs it once
- A client that got an answer is no proxy failure, nuclei and the screenshot report a proxy that failed them
- A proxy failure in an HTTP scanner is a finding of that scanner, a 407 inside the https tunnel is the target's
- A proxy exception with a port or a range target bypasses the proxy, a proxy 407 is an error, nuclei blames the proxy only when it is dead
- Chromium gets the proxy with its credentials, raw-socket scanners say they go direct
- Nuclei follows the proxy, a failing one is logged, its JSON stats are read
- Scanners reach a public target through the proxy, an exception directly, and log a failing proxy
- A failed template refresh says why, and leaves nuclei's output in the log
- A template refresh succeeds on nuclei's output, not its exit code; a refused one takes no quota
- Read-only nuclei templates come with the image, and the admin is told
- Refresh the nuclei templates without -disable-update-check, which turned it off
- A database not ready at start-up still leaves a readable NO_PROXY
- A database not ready at start-up still leaves a readable NO_PROXY (shared)
- A lowercase deployment proxy exempts the internal services too
- A lowercase deployment proxy exempts the internal services too (shared)
- An IPv6 range in the deployment's NO_PROXY is left out, it breaks httpx
- An IPv6 range in the deployment's NO_PROXY is left out, it breaks httpx (shared)
- APP_URL is not internal, a deployment's range is kept as written
- APP_URL is not internal, a deployment's range is kept as written (shared)
- The scanners and the screenshot browser ignore only the proxy Pilot pushed, a standalone .env proxy still applies
- The deployment's own proxy is the base Pilot overrides, never erased (shared)
- A clear message for an IPv6 exception with a port
- A clear message for an IPv6 exception with a port (shared)
- The takeover check reaches its target directly too
- Proxy exceptions take a port or an underscore, refuse ranges, log an unreadable one
- Proxy exceptions take a port or an underscore, refuse ranges, log an unreadable one (shared)
- The scanners reach their target directly, the pushed proxy is for the module's own calls
- Log an outbound proxy out of reach, not only one that refuses
- Scanners reach a target in the proxy exceptions directly, and log a proxy refusal
- Validate proxy exceptions, match ranges and wildcards, keep the deployment's NO_PROXY
- Validate proxy exceptions, match ranges and wildcards, keep the deployment's NO_PROXY (shared)
- Internal services bypass the pushed proxy, and an empty push clears a stale row
- Internal services bypass the pushed proxy, and an empty push clears a stale row (shared)
- One URL per proxy value, keep the pushed proxy out of backups, say when it cannot be decrypted
- A proxy value is one URL, and an unreadable one is not announced restored (shared)
- Pass the pushed proxy to nuclei, warn that nmap cannot use it
- Keep the pushed proxy across restarts, and let Pilot clear it
- Store the outbound proxy pushed by Pilot and restore it at start-up (shared)
- Store the custom LLM label sent with the AI keys (ai)
- Accept the outbound proxy pushed by Pilot
- Accept the custom LLM config pushed by Pilot
- Ship the SSRF guard the custom LLM provider imports
- Tolerate only the missing suite-only file
- Start without the suite-only routes
- Scan all does not alert for a partial scan
- Count a crt.sh outage only when neither lookalike query answered
- Query a large run's alert in chunks
- The CT window is saved only while ct_logs is ticked
- An alert carries the findings its own scan inserted or reopened
- Alert on new findings from manual scans too
- Hidden typosquatting settings are not saved; help on the CT window
- Group the report's top hosts on the host a finding names
- Name the lookalike host on its certificate finding, count only crt.sh outages
- Reposition modal dropdowns on scroll; drop audit webapp orphan (ui)
- Actions filter, project form and action modal UX
- Distinguish the most-severe level from the next on charts (ui)
- Remove a connector's dashboard footprint when its config is cleared

### Changed

- Drop pushed_proxy, the scanners no longer need it
- Drop pushed_proxy, the scanners no longer need it (shared)
- Drop bypasses_proxy, and read the deployment's NO_PROXY at start-up in the test
- Drop bypasses_proxy, only the scanners would use it (shared)

### Documentation

- The page scanners' redirect policy and how each hop is checked
- The custom LLM is also stored, not only held in memory
- State what the report's top-hosts key is

### Tests

- A lookalike whose certificates could not be checked is named
- Js_analysis caps the scripts it fetches and keeps those read
- The scanners that never connect to a name run on one without an address
- The page scanners follow the target's redirects as it says
- A proxy failure is tracked per origin of the scanned target
- A js_analysis script host is resolved once, path parameters kept
- Js_analysis scripts by case, IP and bracketed targets, refused through the proxy
- Js_analysis reads each script on its own host, the root sends SNI
- Without a proxy the raw-socket warning resolves nothing
- An unreachable proxy is the proxy's, its gateway error hides no refused CONNECT
- Directly every js_analysis script is fetched on the address its guard validated
- A malformed script port spares the other scripts, an error on an open tunnel is the target's
- IPv6 target URLs, bracketed and dotted exceptions, target scripts with a port or params
- Js_analysis fetches the target's relative scripts
- A silent proxy is the proxy's, a failed tunnel the target's; dotted exceptions; Chromium exceptions without port
- The scanners through the proxy, follow-ups
- Review follow-ups on the AI agent through the proxy and the restored proxy
- Nuclei's logged output hides the proxy credentials
- The AI agent reaches a custom LLM through the outbound proxy
- Nuclei's template update output stays in the logs, stdout included
- Proxy exception refusals name the entry at fault
- A direct failure records no proxy failure
- Takeover with https refused and http answered, a screenshot captured on the other scheme, ERR_PROXY
- A client answered on another scheme is no proxy failure, nuclei and screenshot proxy failures are findings
- The proxy is asked for the locked IP, a proxy failure is a finding, a 407 inside the tunnel is the target's
- Proxy exceptions with a port, range targets, a proxy 407, nuclei failures unrelated to the proxy
- Chromium gets the proxy with its credentials, raw-socket scanners say they go direct
- Nuclei follows the proxy, a failing one is logged, its JSON stats are read
- Scanners reach a public target through the proxy, an exception directly, and a failing proxy is logged
- A failed template refresh says why and leaves its output in the log; the panel note is locked
- A template refresh that did nothing is not a success, a refused one takes no quota
- Read-only nuclei templates are not refreshed, and the admin is told
- The nuclei template refresh runs a real update
- Settings cleared in Pilot are cleared in the module, before and after a restart
- A database not ready at start-up leaves a readable NO_PROXY, external URLs are not internal
- A restart starts from the stored rows, a lowercase deployment proxy exempts the internal services
- An IPv6 range in the deployment's NO_PROXY is left out, logged
- APP_URL is not internal, a deployment's range is kept, the shell's proxy never leaks in
- The scanners and the screenshot browser ignore only the proxy Pilot pushed
- The deployment's own proxy is the base Pilot overrides, http_proxy covered too
- Every add-on reaching the scanned target ignores the proxy, takeover included
- Proxy exceptions with a port or an underscore are kept, ranges are refused, an unreadable one is logged
- A backup and a restore leave out what Pilot pushes
- The scanners reach their target directly, never through the pushed proxy
- An unreachable proxy is logged, a direct failure is not blamed on it
- Scanners reach a target in the proxy exceptions directly, and log a proxy refusal
- Proxy exceptions are validated, matched with ranges and wildcards, and the deployment's kept
- Internal services bypass the pushed proxy, a stale row clears, logs hold the host only
- A proxy value is one URL, and an unreadable one is not announced restored
- Nmap discovery warns about the proxy, nuclei's proxy file goes on timeout
- Nuclei follows the pushed proxy, nmap says it cannot
- The pushed proxy is stored, restored at start-up and clearable
- The stored custom LLM, label included, survives a restart
- The outbound proxy pushed by Pilot reaches the module
- The custom LLM pushed by Pilot is the one Surface uses
- Call a configured custom LLM through the SSRF guard
- Lock the measure relay and the LLM fallback in both builds
- Lock the exact module each suite-only guard tolerates
- Lock the single Scan all alert and the chunked alert query
- Alert scope for batched findings, Scan all and large runs

### Maintenance

- Proxy_common gains export_proxy (unused here)
- Renumber the lookalike certificate alert FEAT-55

## 1.5.2 — 2026-10-05

### Fixed

- Nuclei templates v10.4.9, every template compiles

## 1.5.1 — 2026-10-03

### Fixed

- nuclei 3.11.1 (was 3.8.0); the release zip and the templates archive are checked against their official sha256 before extraction, which is done with the safe `data` filter.

## 1.5.0 — 2026-10-03

### Added

- Non-conformity and derogation register: declare a non-conformity on one or several items, carry its remediation with corrective measures, or grant a time-boxed derogation; a derogation never counts as compliant.
- Register actions follow the module role and the projects the user may read; a read-only account writes nothing.
- Linked measures show their status, open for editing from the record, and must be done before the record closes.
- The host card edits the full asset, not only its scanners.

### Fixed

- Deleting a finding settles a pending request too; a single deletion no longer fails.
- A derogation never raises the Surface score; the derogated count sits with the banner tiles.
- Client add-ons install their Python dependencies from a hashed lock (`BASE_LOCK=… tests/lock-deps.sh <add-on>`); without one, only what the image already holds is accepted. **A client add-on that adds a package must now ship its lock.**
- Forms lay out on the shared form grid and collapse to one column below 768 px; checkboxes sit on the line of their label.
- Muted text keeps AA contrast on every background; one shared signed-in user block in the toolbar.
- Picking a person closes the result list.
- Security updates: PyJWT 2.15.0 (GHSA-42vr-xj54-vc7v), anyio 4.14.2 (GHSA-82r6-8w77-94w6).

### Changed

- The image installs a complete dependency lock with hashes (`requirements-lock.txt`), transitive dependencies included; the unit tests run on that same lock.

### Documentation

- Comments and documentation point only at files shipped in this repository.
