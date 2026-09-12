cat > REQUIREMENTS.md <<'EOF'
# Sovereign Core Requirements

Sovereign must eventually be able to:

1. Accept a high-level software objective.
2. Clone or open repositories.
3. Understand unfamiliar codebases.
4. Persist project understanding across sessions.
5. Decompose work into tasks and dependencies.
6. Select appropriate agent roles and skills.
7. Retrieve only the context required for the current task.
8. Modify files safely.
9. Install dependencies under policy.
10. Run commands, builds and tests.
11. Debug failures autonomously.
12. Verify completion deterministically.
13. Resume after process or machine restart.
14. Learn reusable procedures from successful and failed work.
15. Discover additional tools, APIs and MCP servers when required.
16. Run primarily with local models.
17. Operate within an 8 GB M1 memory budget.
18. Keep project execution state outside conversational history.
19. Preserve provenance for derived code facts.
20. Keep all major external components replaceable through adapters.

The LLM is not the system controller.

Sovereign Controller owns authoritative project and execution state.
EOF