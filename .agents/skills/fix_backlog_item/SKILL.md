# Skill: Fix Backlog Item

## Protocol

This skill provides a structured, TDD-focused protocol for resolving an entry in `docs/internals/code_issues_backlog.md`.

### 1. Research & Analysis
- **Read the Entry:** Carefully read the Context, Failure Hypothesis, and Needed/Recommendation sections of the backlog entry.
- **Locate Targets:** Identify the target files and symbols mentioned. Use `grep_search` to find all relevant call sites.
- **Verify State:** Confirm if the issue is still present in the current codebase.

### 2. TDD Reproduction (Mandatory)
- **Identify Test Target:** Find the existing test file for the component or create a new one (e.g., `ReproductionTest.kt`).
- **Write Failing Test:** Create a minimal, self-contained test case that triggers the documented failure or behavior.
- **Verify Failure:** Run the test to confirm it fails as expected. **Do not proceed until the failure is empirically reproduced.**

### 3. Implementation
- **Surgical Fix:** Apply the minimal code change required to resolve the issue while adhering to all project safety invariants (see root `AGENTS.md`).
- **Verify Success:** Run the reproduction test again; it must now pass.
- **Regression Check:** Run the full module check (e.g., `./scripts/run_tests.sh`) to ensure no regressions were introduced.

### 4. Finalization & Logging
- **Update Backlog:** Mark the entry as `[RESOLVED]` in `docs/internals/code_issues_backlog.md`.
- **Add Reference:** Include a brief note on how it was fixed and a reference to the commit/PR.
- **Clean Up:** Remove any temporary reproduction tests unless they provide long-term value.
