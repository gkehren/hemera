# Hemera documentation

This directory captures the project's current direction and implemented
contracts. It is the baseline for architecture decisions, scope discussions,
and future contributor documentation.

## Start here

1. [Installation and usage guide](installation-and-usage.md) provides
   installation, configuration, CLI reference, and automation examples.
2. [Vision, direction, and objectives](vision-and-goals.md) explains why Hemera
   exists, what success means, and how product decisions should be made.
3. [Architecture](architecture.md) describes the implemented analysis pipeline,
   its main boundaries, and explicitly labeled future extensions.
4. [Roadmap](roadmap.md) is the authoritative source for implementation order
   and status and breaks delivery into incremental, testable milestones.
5. [Security and ethical boundaries](security-and-ethics.md) defines the safety
   requirements and explicit non-goals.
6. [Detector rule schema V2](detector-rules.md) documents the implemented rule,
   matching, and confidence-scoring contracts.
7. [Detector family support standard](detector-support-standard.md) defines the
   quality criteria, fixture requirements, and evidence/scoring rationale for
   supported detector families.
8. [Regression corpus and accuracy standards](regression-and-accuracy.md) documents
   the synthetic fixture corpus, accuracy metrics, and false-positive/negative rates.
9. [Detector limitations and operational boundaries](detector-limitations.md) details
   the known limitations, blind spots, and evasion profiles for all built-in rules.
10. [JSON report schema V6](report-schema.md) documents the versioned,
    experimental pre-release automation output from
    `hemera scan --format json`.

## Documentation status

Documents distinguish implemented behavior from planned behavior. Architectural
decisions and user-facing formats should be recorded here and updated alongside
the relevant code changes. Implementation status is maintained in the roadmap,
not independently in the source brief.
