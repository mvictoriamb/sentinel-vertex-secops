# Sentinel: ML-Driven Security Triage and Investigation on Vertex AI

Sentinel is an end-to-end security operations platform designed to prioritize Windows endpoint alerts using calibrated tabular machine learning and investigate high-priority episodes through a bounded Gemini agent on Google Cloud Vertex AI.

## Project Objective

Security operations centers face high alert volumes dominated by benign administrative noise. Sentinel addresses this through a two-stage architecture:
1. **Statistical Prioritization (Tabular ML):** Groups raw Windows Sysmon telemetry into bounded investigation episodes, extracts point-in-time features without temporal leakage, and scores episodes using calibrated gradient-boosted trees (XGBoost) deployed on Vertex AI.
2. **Bounded Autonomous Investigation (GenAI Agent):** Dispatches high-priority episodes to a constrained Gemini agent (`google-genai`) equipped with read-only diagnostic tools to gather context, cross-reference MITRE ATT&CK techniques, and produce evidence-linked reports for human analysts.

## Architecture Overview

### Online Triage and Investigation Flow
`Sysmon Telemetry -> Schema Validation -> Episode Construction -> Decision-Time Feature Extraction -> Vertex AI Prediction Endpoint (Prioritization) -> Investigation Queue -> Bounded Gemini Agent -> Analyst Report`

### Core Engineering Principles
* **Temporal Integrity:** All feature extraction and context retrieval enforce strict decision-time cutoffs to prevent future-information leakage during training and evaluation.
* **Data/Instruction Separation:** Telemetry strings (such as process command lines) are treated as untrusted inputs to defend the investigation agent against indirect prompt injection.
* **Bounded Autonomy:** The investigation agent operates under strict step, token, and timeout budgets with read-only tool access. It supports explicit abstention (`insufficient_evidence`) and cannot execute containment actions autonomously.
* **Comparative Evaluation:** System performance is evaluated against deterministic heuristics and fixed-workflow baselines across realistic base rates.

## Repository Structure

```text
sentinel-vertex-secops/
├── src/
│   └── telemetry.py       # Pydantic schemas for Sysmon events and investigation episodes
├── tests/                 # Unit tests for schema validation and temporal leakage prevention
├── .gitignore
└── README.md
```

## Development Status & Roadmap

- [x] **Milestone 1.1:** Core telemetry and investigation episode data contracts (`Pydantic`).
- [ ] **Milestone 1.2:** Leakage-proof `EpisodeBuilder` and grouped dataset splitting.
- [ ] **Milestone 1.3:** Local baseline comparison (Heuristics vs. Logistic Regression vs. Calibrated XGBoost).
- [ ] **Milestone 2:** Vertex AI Custom Training, Experiment Tracking, and Model Registry integration.
- [ ] **Milestone 3:** Bounded Gemini investigation agent (`google-genai`) and 4-way evaluation harness.
- [ ] **Milestone 4:** Cloud Run deployment, Infrastructure as Code (Terraform), and Analyst UI.

## Local Setup

### Prerequisites

- Python 3.11+
- [`uv`](https://docs.astral.sh/uv/)

### Installation

1. **Create a virtual environment:**

   ```powershell
   uv venv
   ```

2. **Activate the virtual environment (Windows PowerShell):**

   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

3. **Install core dependencies:**

   ```powershell
   uv pip install pydantic pandas scikit-learn xgboost pytest google-genai google-cloud-aiplatform
   ```
