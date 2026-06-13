# Contributing to mazewall

Thank you for your interest in contributing to **mazewall**.

mazewall sits at the intersection of security, Linux kernel internals, and JVM runtime mechanics. It is a security-critical library that interfaces directly with the Linux kernel and JVM threads. Errors here lead to silent security bypasses or permanent JVM deadlocks — not just bugs.

As a contributor, keep the north star in mind: give developers easy-to-use tools to restrict code execution as much as possible, with automated SBoB generation and surgical sandboxing for the most dangerous parts of their code.

---

## Before You Start

**Read these first — they contain non-negotiable safety constraints:**

| Document | Why it matters |
|---|---|
| [AGENTS.md](AGENTS.md) | Hard boundaries for AI and human contributors: what never to block, what never to bypass |
| [enforcer/AGENTS.md](enforcer/AGENTS.md) | JVM coordination syscalls, Loom carrier thread rules, FFM errno safety |
| [profiler/AGENTS.md](profiler/AGENTS.md) | USER_NOTIF ACK loop deadlock prevention, ptrace scope, strace parsing |
| [docs/internals/architectural_map.md](docs/internals/architectural_map.md) | Component diagram, the ACK loop sequence, cross-module dependencies |
| [docs/internals/SECURITY_CONSIDERATIONS.md](docs/internals/SECURITY_CONSIDERATIONS.md) | Full threat model — what mazewall stops and what it doesn't |

---

## Architecture in One Paragraph

mazewall has two production modules: **`:enforcer`** (zero-dependency production runtime — BPF compilation, filter installation, Landlock, `ContainedExecutors`) and **`:profiler`** (dev/test tool — `USER_NOTIF` daemon, iterative Landlock profiler, `BillOfBehavior` compiler). The demo subprojects in `demos/` consume both. The most critical architectural constraint is the profiler's **ACK loop**: the daemon must always ACK every intercepted syscall or the worker thread deadlocks permanently. See `architectural_map.md` for the full sequence diagram.

---

## Guidelines

1. **Security first:** Never implement silent fallback or bypass behavior. The default is fail-closed. See [AGENTS.md §2](AGENTS.md).
2. **TDD:** Reproduce bugs with a failing test before fixing. New features get tests before implementation.
3. **Log issues:** Any kernel behavior discovery, JVM quirk, or security nuance you find goes in [`docs/internals/code_issues_backlog.md`](docs/internals/code_issues_backlog.md).
4. **Discuss major changes:** Open a GitHub issue before starting large architectural or API changes.
5. **Code style:** Kotlin idiomatic style, Detekt clean, ktlint clean (`./scripts/lint.sh`).

---

## Development Setup

You need a **Linux host or container with kernel ≥ 6.2** for integration tests. Unit tests run on any host.

### Option A: Run directly on a Linux host

```bash
# Unit tests only (fast, no kernel interaction)
./gradlew test

# Full integration suite
./scripts/run_tests.sh

# Lint
./scripts/lint.sh
```

### Option B: Isolated Podman environment (recommended)

```bash
podman compose -f infra/dev/compose.yml up -d
podman compose -f infra/dev/compose.yml exec mazewall ./gradlew check
```

The Podman environment provides the correct kernel capabilities and nested seccomp profile needed for integration tests.

### Module-Level Checks

```bash
./gradlew :enforcer:check    # Jacoco thresholds: LinuxNative ≥ 78%, core ≥ 80%
./gradlew :profiler:check    # Jacoco thresholds: Profiler ≥ 60%
```

---

## Responsible Disclosure

If you discover a security vulnerability, **do not open a public issue**. Follow standard responsible disclosure — contact the maintainer directly before publishing.
