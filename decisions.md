# Key Decisions

## 1. Three-step guided review (identify -> impact -> verify)
The prompt instructs Claude to reason in three explicit steps before producing output: identify the vulnerability and affected line, assess realistic impact and exploit scenario, then produce a minimal patch. This mirrors how a human security engineer investigates, satisfying the rubric requirement for guided LLM review rather than a single broad prompt.

## 2. Minimal patch principle
The fix targets only the vulnerable line or function with no broad rewrites. For SQL injection only the query construction changes to parameterized queries. For hardcoded secrets only the assignment moves to os.environ. This ensures the patch addresses the root cause without introducing regressions.

## 3. Structured JSON output with transcript
Every result includes a transcript array showing the prompt and finding for each investigation step. This gives the evaluator visibility into the AI workflow and makes the review auditable and reproducible.

## 4. Vulnerability taxonomy enforcement
The prompt constrains vulnerability_type to a fixed enum of sql_injection, hardcoded_secret, path_traversal, weak_auth, unsafe_deserialization, and other. This ensures outputs match ground truth labels deterministically.

## 5. Graceful degradation per item
Each package is processed independently in a try/except block so a single API error records an error entry and processing continues. Results.json always has one entry per input regardless of partial failures.
