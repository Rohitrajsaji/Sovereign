cat > NON_GOALS.md <<'EOF'
# Sovereign Architectural Freedom

This document intentionally imposes very few architectural restrictions.

GPT-6 Astra is expected to act as the principal architect and determine the
strongest practical architecture after deeply inspecting the supplied
repositories and requirements.

The objective is NOT minimalism for its own sake.

The objective is the strongest autonomous local software-engineering system
that can realistically operate on the target MacBook Air M1 with 8 GB unified
memory.

Astra may:

- reuse open-source components directly where appropriate
- adapt architectural patterns
- combine ideas from multiple repositories
- create new Sovereign-specific components
- introduce databases, indexes, graphs, services or runtimes when justified
- replace earlier architectural assumptions
- propose staged architecture where advanced capabilities are introduced later
- reject an existing idea if a demonstrably better architecture exists

All supplied repositories must be seriously evaluated for useful capabilities,
patterns, algorithms, workflows, agents, skills, tooling or architecture.

They are not merely references to be summarized.

However, using a repository does not necessarily mean running the entire
project as a permanent dependency.

Astra should determine the most efficient form of reuse:

- direct dependency
- embedded component
- adapter
- extracted subsystem
- protocol compatibility
- architecture pattern
- algorithm
- skill source
- agent source
- knowledge source
- optional on-demand capability

Hard constraints remain:

1. Sovereign must run primarily locally.
2. The target machine is a MacBook Air M1 with 8 GB unified memory.
3. The normal system must not depend on paid cloud APIs.
4. The system must remain useful when external AI services are unavailable.
5. Resource usage must be engineered deliberately.
6. Autonomous work must be verifiable rather than merely claimed complete.
7. Long-running work must survive context exhaustion and process restart.
8. Context and token usage must be aggressively optimized.
9. The system must be capable of evolving beyond its initial implementation.

Everything else is an architectural decision for Astra.
EOF