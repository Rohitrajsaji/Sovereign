cat > MACHINE.md <<'EOF'
# Target Machine

Hardware:
- MacBook Air M1
- Apple Silicon
- 8 GB unified memory
- 512 GB SSD

Environment:
- macOS
- Git 2.50.1
- Python 3.14.7
- Node.js 22.23.2
- Approximately 107 GB free disk space at planning time

Operating assumptions:
- Local models are the default runtime.
- llama.cpp / Metal or equivalent local inference should be preferred.
- Prefer one resident LLM at a time.
- Multiple logical agents should share the same model serially.
- Docker must not be assumed to run permanently.
- Browsers should be demand-loaded.
- Language servers should be demand-loaded.
- RAM and swap pressure are architectural constraints.
- Cloud APIs are optional, not required.
- The system must still work if Astra is unavailable.

Primary optimization target:

verified useful engineering work / RAM / time / model tokens
EOF