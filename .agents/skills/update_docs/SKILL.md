# Skill: Update Documentation

## Protocol

This skill provides a protocol for keeping design and internal documentation in sync with architectural changes.

### 1. Identify Change Impact
- **Code Change:** Analyze the code modification (e.g., refactoring `ContainerStateRegistry`, changing a `Policy` preset).
- **Find References:** Search `docs/internals/*.md` and `presentation/*.md` for symbols or concepts affected by the change.

### 2. Verify Drift
- **Compare:** Compare the current code behavior with the claims made in the documentation.
- **Identify Gaps:** Look for renamed methods, changed thread-local variables, or updated security invariants that are no longer accurately described.

### 3. Synchronize (Readability & Modularity)
- **Update Design Docs:** Modify `containment_design.md` or `profiler_design.md` to reflect the new reality. Ensure the logic is modularly described.
- **Update presentation:** If the change affects how developers interact with the library, update the relevant files in `docs/presentation/`.
- **Maintain Consistency:** Ensure that the same terminology is used across code, KDocs, and Markdown files. Terminology must be precise and consistent with the established `NativeEngine` trait nomenclature.
- **Readability:** Ensure that updated documentation remains accessible and free of jargon that hasn't been defined.

### 4. Backlog Audit
- **Check Backlog:** Scan `docs/internals/code_issues_backlog.md` for "Documentation Drift" entries.
- **Resolve:** If your change resolves an existing drift entry, mark it as `[RESOLVED]`.
