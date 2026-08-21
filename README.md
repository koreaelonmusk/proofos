# ProofOS

**Evidence-first autonomous agents that prove their work before claiming completion.**

Google All Things Agentic Hackathon 2026  
Target track: **Fortified Enterprise Fleet**

## Core invariant

> A completion claim is never accepted unless the required evidence exists and validates.

## P0 flow

```text
User Goal
  -> Gemini 3.5 Flash / Google ADK Agent
  -> Completion Claim
  -> Evidence Verifier
  -> VERIFIED | ABSTAIN
```

## Stack

- Gemini 3.5 Flash
- Google Agent Development Kit (ADK)
- Python 3.11+
- Google Cloud Run
- Vertex AI
- Firestore planned for the evidence ledger

## Repository layout

```text
.
├── proofos_agent/
│   ├── __init__.py
│   └── agent.py
├── proofos/
│   ├── __init__.py
│   └── verifier.py
├── tests/
│   └── test_verifier.py
├── docs/
│   └── architecture.md
├── .github/
│   └── workflows/
│       └── ci.yml
├── .env.example
├── requirements.txt
└── README.md
```

## Local verification

The verification kernel is deterministic and has no model dependency:

```bash
python -m unittest discover -s tests -v
```

## Google Cloud setup

Create or select a Google Cloud project with billing enabled.

```bash
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
gcloud services enable run.googleapis.com aiplatform.googleapis.com cloudbuild.googleapis.com
```

Create your local environment file:

```bash
cp .env.example .env
```

Set:

```text
GOOGLE_GENAI_USE_VERTEXAI=TRUE
GOOGLE_CLOUD_PROJECT=YOUR_PROJECT_ID
GOOGLE_CLOUD_LOCATION=us-central1
```

## Run locally with ADK

Install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Then use the ADK tooling to run the agent locally.

## Deploy to Cloud Run

From the repository root:

```bash
gcloud run deploy proofos --source .
```

When prompted, select a region and allow public access for the hackathon demo if your account policy permits it.

After deployment, preserve the generated `.run.app` URL plus Cloud Run / Vertex AI logs as demo evidence.

## P0 acceptance criteria

- [x] Verification contract exists
- [x] Missing evidence => ABSTAIN
- [x] Invalid evidence => ABSTAIN
- [x] Valid required evidence => VERIFIED
- [x] Deterministic verifier tests pass
- [ ] Live Gemini 3.5 Flash call succeeds
- [ ] ADK invokes verifier tool in a real session
- [ ] Cloud Run deployment succeeds
- [ ] Cloud execution evidence captured

## Hackathon disclosure

This repository is intended to contain work created during the hackathon submission period. Any pre-existing code or external assets must be clearly disclosed before submission.
