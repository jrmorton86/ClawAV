# Runtime Abstraction & De-hardcoding — Phase 1 Design

## Why this plan exists

ClawTower currently delivers strong detection coverage, but core threat logic is spread across hardcoded Rust modules (`behavior.rs`, scanner registration, parser-specific mappings). This makes tuning and extending coverage slow, risky, and review-heavy.

Phase 1 establishes stable abstraction boundaries and data contracts without changing runtime behavior.

## Scope (Phase 1)

This phase is intentionally non-invasive:

- Add architectural interfaces (traits + registry scaffolding)
- Define canonical rule envelope schema
- Define scanner catalog format
- Keep current source wiring and detector behavior unchanged
- Do **not** remove existing hardcoded rules yet

## Out of scope (Phase 1)

- Full migration of `behavior.rs` patterns
- Full scanner scheduling rewrite
- Runtime hot-reload for all rule packs
- Cross-module crate split

## Design principles

1. **No security regression:** preserve fail-secure defaults and aggregator choke point.
2. **Parity-first migration:** old and new evaluators should produce equivalent alerts before cutover.
3. **Data-driven behavior:** move policy/rule content to signed, versioned artifacts.
4. **Stable execution core:** runtime primitives remain in Rust and are heavily tested.

## Target interfaces

Phase 1 introduces interfaces under `src/detect/traits.rs`, `src/sources/traits.rs`, `src/runtime/registry.rs`.

### `EventSource`

Purpose: standardize source startup and metadata.

- source ID/name
- health signal (best effort)
- async start into alert/event channels

### `Detector`

Purpose: normalize how matching logic runs.

- detector ID/version
- source compatibility declaration
- evaluation returns proposals; runtime owns final alert publication path

### `ScannerPlugin`

Purpose: support catalog-driven scanner orchestration.

- scanner ID/category
- capability requirements
- run method returning normalized `ScanOutcome`

### `RuleProvider`

Purpose: unify loading/validation/reload of policy/rule packs.

- load signed bundle
- schema validation
- monotonic version checks
- rollback on invalid update

## Canonical rule envelope

Schema file: `rules/schema/rule-envelope.schema.json`

Core fields:

- `id`, `version`, `enabled`, `description`, `category`, `severity`
- `source` (auditd/network/scanner/etc)
- `selector` (field-level routing)
- `match` (regex/contains/eq/glob)
- `condition` (boolean composition)
- `action` (alert/block/quarantine/tag)
- `throttle` and `dedup` hints
- optional inline tests (`fixtures`)

This envelope is an IR (intermediate representation). Existing YAML policy and BarnacleDefense JSON can be adapted into it.

## Scanner catalog format

Catalog file: `scans/catalog.example.toml`

Goals:

- Make scanner scheduling declarative
- Standardize timeout/retry/escalation behavior
- Enable per-environment overrides via config layering

Each scanner entry defines:

- `id`, `enabled`, `interval_seconds`
- `timeout_seconds`, `requires_root`
- `severity_on_warn`, `severity_on_fail`
- optional distro/arch predicates

## Migration roadmap

### Phase 1 (this change)

- Add schema + scaffolding traits + registry skeleton
- Add example catalog
- Add docs for contributor usage

### Phase 2

- Wrap current hardcoded behavior engine behind `Detector`
- Build parity replay tests against known event corpus

### Phase 3

- Move behavior pattern sets to external rule packs
- Introduce signed bundle loading and version pinning

### Phase 4

- Convert scanner orchestrator to catalog-driven runtime
- Add policy/rule hot-reload + safe rollback

## Security invariants (must remain hardcoded)

These controls are not externalized:

- Aggregator-only alert fanout enforcement
- Update signature trust anchor and signature verification path
- Admin auth primitive + minimum work factors
- Immutable file and self-protection deny rules in privileged paths
- Fail-secure behavior when config/rules are missing or invalid

## CI additions required for migration safety

1. `rule-lint`: schema + duplicate ID checks + regex sanity
2. `parity-replay`: compare old and new detector outputs on canned logs
3. `invariant-tests`: assert aggregator choke point and fail-secure defaults
4. `bundle-signature-test`: verify signed rule bundle acceptance/rejection logic

## Success criteria for Phase 1

- New interfaces compile and are documented
- No behavior change in default runtime
- Schema and catalog examples validate (via CI rule-lint)
- Follow-up PRs can migrate logic incrementally without redesign
