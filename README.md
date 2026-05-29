# Insider Threat Detection System

A machine learning pipeline that detects anomalous user behavior in organizational environments using unsupervised behavioral analytics. Built as the capstone project for MSIT 5910 at the University of the People.

---

## Overview

Insider threats are one of the most difficult challenges in cybersecurity because the people involved already have legitimate credentials and access. Traditional rule-based security tools fail to detect them because malicious insider behavior often looks identical to normal activity in its early stages.

This system addresses that problem by analyzing multi-source user activity logs — login records, file access, email activity, and USB device usage — and applying the Isolation Forest unsupervised anomaly detection algorithm to surface users whose behavioral patterns deviate significantly from the broader population. The output is a normalized 0–100 risk score for every user, classified into Low, Medium, and High risk tiers, supported by five analytical visualization outputs designed for security analyst review.

No labeled training data is required. The system learns what normal looks like and flags deviation.

---

## Key Results

| Metric | Value |
|---|---|
| Users analysed | 500 |
| Total events processed | 541,985 |
| Anomalies flagged | 25 (5.0%) |
| High risk users | 15 (3.0%) |
| Recall (ground truth) | 1.00 — zero threats missed |
| Precision | 0.60 |
| F1 Score | 0.75 |
| False positive rate | 2.0% |
| Model execution time | < 10 seconds |
| Acceptance tests passed | 8/8 (100%) |

---

## Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3 |
| Data processing | pandas, NumPy |
| Machine learning | scikit-learn (Isolation Forest, StandardScaler) |
| Visualisation | matplotlib, seaborn |
| Development environment | Google Colab |
| Data storage | Google Drive (shared CSV pipeline) |
| Version control | Git and GitHub |
| Deployment target | Docker + Google Cloud Run / AWS ECS |

---

## System Architecture

The system is a five-stage modular pipeline. Each stage runs as a separate notebook and communicates with the next stage through shared CSV files in Google Drive.

```
Login logs ──┐
File logs  ──┤──► Module 1: Data Collection & Preprocessing
Email logs ──┤         │
USB logs   ──┘         ▼ master_log.csv
                  Module 2: Feature Engineering
                       │ user_features.csv
                       ▼
                  Module 3: Anomaly Detection (Isolation Forest)
                       │ anomaly_scores.csv
                       ▼
                  Module 4: Risk Scoring & Classification
                       │ Low / Medium / High tiers
                       ▼
                  Module 5: Visualisation & Analyst Dashboard
                       │ 5 chart outputs
```

---

## Features

- **Multi-source data ingestion** — merges login, file, email, and USB activity logs into a unified behavioral dataset
- **26 engineered behavioral features** — spanning login timing, file access patterns, email communication behavior, and device usage
- **Unsupervised anomaly detection** — no labeled training data required
- **Interpretable risk scoring** — normalized 0–100 scale with Low, Medium, and High tier classification
- **5 analytical visualizations** — risk distribution histogram, top-20 risk users, feature correlation heatmap, off-hours activity boxplot, and email vs USB scatter plot
- **Deterministic outputs** — fixed random seed ensures fully reproducible results
- **Modular architecture** — each pipeline stage can be tested and updated independently

---

## Project Structure

```
insider-threat-detection-system/
│
├── src/                          # Source notebooks
│   ├── 01_data_generation.ipynb  # Synthetic data generation
│   ├── 02_preprocessing.ipynb    # Data cleaning and feature extraction
│   ├── 03_feature_engineering.ipynb  # Behavioural feature computation
│   ├── 04_model.ipynb            # Isolation Forest training and scoring
│   ├── 05_visualization.ipynb    # Chart generation
│   └── Confusion_Matrix.ipynb    # Model evaluation and LOF comparison
│
├── design/                       # Architecture diagrams
│   └── system_architecture.drawio
│
├── docs/                         # Project documentation and reports
│
├── results/                      # Output charts and CSV files
│   └── charts/                   # PNG visualization outputs
│
└── README.md
```

---

## Getting Started

### Prerequisites

- Python 3.9 or higher
- Google Colab account (recommended) or local Python environment
- Google Drive (for shared pipeline storage)

### Installation

```bash
# Clone the repository
git clone https://github.com/Flipflop-ux/insider-threat-detection-system
cd insider-threat-detection-system

# Install dependencies
pip install pandas numpy scikit-learn matplotlib seaborn
```

### Running the Pipeline

Run the notebooks in order from your Google Colab or local Jupyter environment:

```
1. src/01_data_generation.ipynb      — generates synthetic CERT 4.2 dataset
2. src/02_preprocessing.ipynb        — cleans and merges data sources
3. src/03_feature_engineering.ipynb  — computes 26 per-user features
4. src/04_model.ipynb                — trains Isolation Forest, outputs risk scores
5. src/05_visualization.ipynb        — generates 5 analytical charts
```

Each notebook saves its output to Google Drive automatically before the next stage loads it.

### Configuration

Key parameters are set at the top of the model notebook:

```python
CONTAMINATION  = 0.05   # Proportion of users expected to be anomalous
N_ESTIMATORS   = 200    # Number of Isolation Forest trees
RANDOM_STATE   = 42     # Fixed seed for reproducibility
RISK_LOW       = 40     # Score threshold for Low / Medium boundary
RISK_HIGH      = 70     # Score threshold for Medium / High boundary
```

---

## Deployment

For production deployment, the pipeline is designed to run as a Docker containerized batch job on a cloud platform.

```bash
# Build Docker image
docker build -t insider-threat-detection .

# Run containerized pipeline
docker run -v $(pwd)/data:/app/data insider-threat-detection
```

Recommended platforms: Google Cloud Run or AWS Elastic Container Service (ECS).
Suggested schedule: nightly or weekly batch run on new activity log exports.

---

## Version History

| Version | Description |
|---|---|
| v0.1.0 | Initial development — repository structure, preprocessing and feature engineering |
| v1.0.0 | Model training complete — Isolation Forest pipeline, risk scoring validated |
| v1.1.0 | Testing and visualization complete — confusion matrix, LOF comparison, 8/8 acceptance tests passed |
| v1.2.0 | System testing and maintenance complete — deployment planning, maintenance documentation |

---

## Evaluation

Model performance was evaluated against the known ground truth of 15 embedded malicious users in the synthetic dataset.

```
              precision    recall  f1-score   support

      Normal       1.00      0.98      0.99       485
   Malicious       0.60      1.00      0.75        15

    accuracy                           0.98       500
```

A Local Outlier Factor (LOF) comparison confirmed identical metrics, validating that the behavioral feature engineering — rather than the algorithm choice — is the primary driver of detection performance.

---

## Limitations

- Evaluated on synthetic data only — real organizational data may produce different results
- Batch processing only — does not support real-time monitoring
- Static feature aggregation — cannot detect gradual behavioral drift over time
- Requires human analyst review for all High risk flags before any action is taken

---

## Future Work

- Validate on larger real-world datasets (tens of thousands of users)
- Add work phone activity data as a new feature dimension
- Implement real-time streaming using Apache Kafka and Apache Flink
- Integrate SHAP explainability values for feature-level risk reasoning
- Build a web-based analyst dashboard for interactive risk review

---

## Branches

| Branch | Purpose |
|---|---|
| `main` | Stable, submission-ready code |
| `development` | Active development and feature work |

---

## Academic Context

This project was completed as the capstone requirement for **MSIT 5910** at the **University of the People**.

**Dataset:** CERT 4.2 Synthetic Insider Threat Dataset — Carnegie Mellon University Software Engineering Institute

**Key references:**
 Liu et al. (2008) — Isolation Forest algorithm
 Homoliak et al. (2020) — Security reference architecture for insider threat detection
 Aggarwal (2021) — Anomaly detection theory

---

## License

This project is open source.
