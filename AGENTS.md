- **First-Principles Thinking**: Identify true goals, constraints, and success criteria first; do not blindly follow conventions.

- **Response Format**: Answer simple questions directly; use `answer-me-with-html` for complex ones.

- **Continuous Learning**: Read `AGENT_LEARNINGS.md` before starting any new task to avoid repeating mistakes. After any mistake, update `AGENT_LEARNINGS.md` with the error made, anti-patterns to avoid, and the better solution.

- **Browser Control**: Use Chrome by default; ask first before controlling Vivaldi.

- **Production Performance**: Include performance overhead in design and acceptance criteria for any release, deployment, or production-related task.

- **UI Minimalism**: Avoid unnecessary secondary labels and descriptions. Let the layout do the explaining.

- **Accessibility Semantics**: When removing redundant visual labels, preserve semantic accessibility attributes in code (e.g., `aria-label`) to keep the UI clean while remaining screen-reader friendly.

- **Research Before Building**: Do not implement unfamiliar features from scratch immediately. Search GitHub for actively maintained open-source projects with clear licenses, and compare their approaches, dependencies, and known issues. Adapt proven designs rather than copying incompatible or unverified code—never pick a library abandoned three years ago as a reference.

- **No Over-Engineering / Speculative Defense**: For highly unlikely edge cases or concurrency races, explain the exact failure mode, probability, and lines of code added, and wait for user approval before implementing. Never bloat code or expand change scope unilaterally just to be "theoretically safer."

- **Validate Once at Boundaries**: Validate external data once at system entry points and rely on the type system internally. Do not repeat defensive checks across internal layers.

- **No Premature Abstraction**: Inline single-use logic locally instead of extracting meaningless helpers. Extract only when reusing code, encapsulating complex logic, or naming a clear concept that genuinely improves readability.

- **Control Complexity**: Avoid unnecessary `try/catch` blocks. Do not split logic artificially if a single function handles it clearly.

- **Code Organization**: Keep the main function focused on the happy path; organize boundary checks and details nearby for readability rather than forcing tiny helper functions for formality.

- **Meaningful Comments Only**: Comment only non-obvious constraints and counter-intuitive behaviors. Never write comments for self-explanatory code.

- **Generated Files**: Never hand-edit auto-generated files; modify the source and regenerate instead.

- **Test Real Implementations**: Test actual implementations rather than duplicating business logic inside tests. Minimize the use of mocks.

- **Respect Existing Workflows**: Follow the repository's existing conventions; do not introduce tools or workflows not already used in the repo.

- **Local Architecture References**: For design or implementation questions, prioritize referencing the CLI implementation in `C:\Users\MrQzs\Desktop\临时站\CLI` and existing analyses in `D:\Code\Quizs\docs\cli设计`, cross-checking against the current codebase. Before adopting external solutions, verify upstream maintenance status, licensing, and known issues.

## Error Handling & Edge-Case Testing

For every new feature or logic change, consider realistic failure modes carefully:

1. **Failure Mode Analysis First**: Before coding, enumerate realistic failure paths—invalid/boundary inputs at entry points, illegal state transitions, and external I/O or resource failures (timeouts, disconnects, corrupted data).
2. **Explicit Error Propagation**: Never swallow errors silently. Return explicit error types/codes and guarantee resource cleanup and state consistency on failure without overusing `try/catch`.
3. **1:1 Negative Test Coverage**: Write dedicated unit tests for every identified error path and recovery branch alongside happy-path tests—preferring real boundary inputs and controlled failure simulation over heavy mocking.

## Branches

- **Never commit directly to `master`.** Work on a short-lived branch cut from `master`, one topic per branch:
  `feature/<topic>` for new features and improvements, `fix/<topic>` for bug fixes, `docs/<topic>` for documentation only
  (topic in lowercase English, words joined with hyphens, e.g. `feature/clip-agent`, `fix/file-paste-system-host`).
- Push the branch and open a pull request; CI must pass.
- Merge into `master` only after the user has verified the change and explicitly says to merge. Merge through the pull request,
  never force-push, and delete the branch afterwards.
- `master` is protected: changes land only through pull requests.
