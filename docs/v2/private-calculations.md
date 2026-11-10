# Private calculation receipts

`create_private_calculation(subject_id, selection_id, selection_sha256,
revision_ids, metric, idempotency_key="")` creates one immutable private receipt.
`get_private_calculation(subject_id, calculation_id)` reads that receipt and
separately reports the saved case's current freshness. Both return
`{"receipt": ..., "freshness": ...}`. Receipt and acknowledgement IDs use the
existing `case_<hex>` private identifier namespace; they cannot be public
research support.

The caller selects exactly two distinct current confirmed revisions already in
the exact signed case, and chooses `delta` or `percent_change`. A case with a
non-null `recorded_as_of` is not eligible for new calculations. An older clinical
collection date in a current confirmed row is eligible. Caller formulas, numeric
values, units, rounding settings, assurance fields and all other unknown request
fields are rejected.

Creation holds one outer private-store write transaction across current case
validation, `RecordsService.compare_observations(..., mode="strict")`, receipt
validation, receipt save and acknowledgement save. The exact pair must be
strictly comparable, with no contextual or excluded row, two `numeric_exact`
results and established clinical chronology. Method, specimen, identity and unit
rules remain those of the production comparator. The operation cannot choose a
passing subset, convert units, impute a censored bound or evaluate arbitrary
expressions. Percent change requires a computed production percent result and
refuses a zero baseline. Zero delta is valid.

The receipt includes its ID/hash, full case binding, the explicit requested
operation and metric, a full input manifest containing the immutable revisions
and their source, row and confirmation bindings, the production comparison
snapshot, the chosen production numeric result and copied arithmetic policy.
Delta preserves the production decimal string and original unit. Percent
preserves the production percent object, including its exact denominator string.
Formula, endpoints, clinical interval, conversion policy and rounding policy are
copied unchanged. Output decimal strings are not rerun through the 128-character
plain-input validator: valid production subtraction can be longer, and percent
can use exponent notation.

`validate_calculation_receipt(receipt, lookup)` accepts an internal authenticated
lookup function `lookup(kind, object_id, subject_id)`. It resolves the immutable
case graph, checks the complete input manifest and reruns the actual production
comparator through a read-only frozen graph view. The frozen view uses the case's
selected-at-capture current rows and captured source conflicts. It never
substitutes a corrected current revision or consults today's projection for
arithmetic. This lets recovery validate a past valid receipt after a correction.

Core replay compares every comparison field except `coverage` and each row's
`source_availability`. Those two fields are informational metadata captured from
the actual comparison at creation; coverage and availability can change without
changing the operands. All row values, kinds, source-backed rows, identities,
assurance, included IDs, clinical order, arithmetic and policy remain exact replay
requirements. Availability loss does not delete a confirmed historical operand;
the receipt does not claim that its source bytes were checked live.

An exact nonempty idempotency-key retry returns the same immutable receipt and
refreshes freshness separately. A reused key with a different case, pair, metric
or request fails. New calculations fail once a selected revision or selected
conflict state becomes stale. A saved valid receipt remains readable with
freshness `stale`; that is validity at creation, not present
clinical applicability or independent authentication of a person.

`validate_calculation_idempotency(acknowledgement, lookup)` validates the exact
receipt reference and reconstructs its request hash for recovery. The opaque
idempotency key determines the private acknowledgement ID and is not copied into
the receipt or acknowledgement payload.

Owned fictional tests cover production comparison calls within the transaction,
bounded long/exponent output, zero baseline, unsupported kinds, unknown and
mismatched context, time ambiguity, exact selection/hash binding, strict unknown
fields, immutable retry, partial-write rollback, tampered graph/receipt shapes,
source metadata changes and reading old receipts after correction. Tests create
fresh private stores with wholly fictional subjects and source metadata. They do
not read real archives, existing private stores or source files and make no
network or model calls.
