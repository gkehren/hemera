# Hemera documentation

This directory captures the project's current direction and implemented
contracts. It is the baseline for architecture decisions, scope discussions,
and future contributor documentation.

## Start here

1. [Vision, direction, and objectives](vision-and-goals.md) explains why Hemera
   exists, what success means, and how product decisions should be made.
2. [Architecture](architecture.md) describes the planned analysis pipeline and
   its main boundaries.
3. [Roadmap](roadmap.md) is the authoritative source for implementation order
   and status and breaks delivery into incremental, testable milestones.
4. [Security and ethical boundaries](security-and-ethics.md) defines the safety
   requirements and explicit non-goals.
5. [Detector rule schema V1](detector-rules.md) documents the implemented rule,
   matching, and confidence-scoring contracts.
6. [JSON report schema V1](report-schema.md) documents the stable automation
   output from `hemera scan --format json`.

## Documentation status

Documents distinguish implemented behavior from planned behavior. Architectural
decisions and user-facing formats should be recorded here and updated alongside
the relevant code changes. Implementation status is maintained in the roadmap,
not independently in the source brief.

The product and vision source brief is the
[Web Protection Scanner Notion page](https://app.notion.com/p/3c076e148bdd812e99d6c69ac2dd7ee8).
