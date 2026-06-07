# Contributing to mazewall

Thank you for your interest in contributing to **mazewall**! 

As a security-critical library that interfaces directly with the Linux kernel and JVM internals, we maintain high standards for correctness, safety, and documentation.

As a contributor, keep our "north star" in mind: our end goal is to give developers easy-to-use tools to restrict code execution as much as possible, with automated SBoB self-restraining and easy "glassbox" sandboxing (portals to WASM, isolates, sidecars) for the most dangerous parts of their code.

## Guidelines

1. **Experimental Nature:** Please keep in mind that this is currently an experimental research proof-of-concept. Stability and API compatibility will change.
2. **Security First:** If you discover a security vulnerability, please do **not** open a public issue. Instead, follow standard responsible disclosure practices (TBD).
3. **Discuss Major Changes:** For large architectural changes or new features, please open an issue to discuss your proposal before starting implementation.
4. **Code Quality:**
    - Adhere to the existing Kotlin style and idiomatic patterns.
    - Ensure all changes pass the automated test suite (`./gradlew test`).
    - Maintain or improve test coverage (verified via Jacoco).
    - Follow the strict engineering mandates documented in the `AGENTS.md` files located in the root and subproject directories.

## Development Setup

To run the full integration test suite, you need a **Linux environment** with a compatible kernel (6.2+). You can run tests directly on your host or use the provided Podman environment.

### Direct Execution
```bash
./gradlew check
```

### Isolated Execution (Podman)
Using Podman ensures a consistent environment and allows for nested seccomp testing via a custom profile:

```bash
podman compose -f infra/dev/compose.yml up -d
podman compose -f infra/dev/compose.yml exec mazewall ./gradlew check
```

We look forward to your contributions!
