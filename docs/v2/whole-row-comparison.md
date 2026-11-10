# Attested whole-row decisions in read projections

The frozen whole-row review includes original values, typed fields, source
anchors and uncertainties. A trusted conversation/operator decision accepts
the displayed unambiguous source proposals. Earlier comparison logic still
treated every `field_status=proposed` as unknown after that decision, causing
known imported values and dates to remain contextual.

The read projection now carries the revision's existing assurance into
`_field_known` and `_strict_time`. Proposed fields may participate only for a
trusted revision. Original extraction statuses, raw rows, anchors and signed
history are unchanged. No user confirmation, field value, mapping or date is
created by this read operation.

Unknown/ambiguous/missing fields stay excluded or contextual. A confirmed
canonical analyte mapping is still required. Report dates, partial dates and
unknown collection times do not become precise collection times. Model-only
rows keep assurance `none`, cannot become strictly comparable and remain
outside the default confirmed case selection.

Synthetic regressions cover the accepted row, immutable original statuses and
negative branches. They do not authenticate a real human decision, establish
semantic or clinical correctness or authorize actual legacy migration.
