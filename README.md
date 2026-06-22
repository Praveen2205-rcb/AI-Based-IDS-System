# AI-Based Intrusion Detection System (IDS)

A hybrid network intrusion detection system that combines a supervised **Artificial Neural Network (ANN)** with an unsupervised **Autoencoder** for real-time threat detection. Models are trained on the [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) dataset with SMOTE class balancing, then deployed against live or simulated Snort alerts.

## Features

- **Dual-model detection** — ANN classifies known attack patterns; Autoencoder flags anomalous traffic via reconstruction error
- **SMOTE balancing** — Handles class imbalance in training data
- **Real-time monitoring** — Snort integration with simulated or live network interface modes
- **Live web dashboard** — Flask + SocketIO dashboard with attack statistics and alert stream
- **Evaluation reports** — Confusion matrices, learning curves, and model comparison plots saved to `results/`

## Architecture

The system has two main phases: an **offline training pipeline** (batch) and an **online monitoring pipeline** (real-time). Both share the same saved models in `models/`.

### High-level system overview

```mermaid
flowchart TB
    subgraph OFFLINE["Phase 1 & 2 — Offline Training (main.py --no-monitor)"]
        DS[(UNSW-NB15 CSVs<br/>data/)]
        LD[load_data.py]
        PP[preprocess.py]
        SM[smote_processing.py]
        ANN_T[ann_model.py]
        AE_T[autoencoder_model.py]
        EV[evaluate.py]
        MD[(models/)]
        RS[(results/)]

        DS --> LD --> PP
        PP --> SM --> ANN_T
        PP --> AE_T
        ANN_T --> EV
        AE_T --> EV
        ANN_T --> MD
        AE_T --> MD
        PP --> MD
        EV --> RS
    end

    subgraph ONLINE["Phase 3 — Real-Time Monitoring"]
        SNORT[Snort NIDS<br/>live or simulate]
        MON[snort_monitor.py]
        PRED[ai_predictor.py]
        OUT1[CLI Terminal<br/>main.py]
        OUT2[Web Dashboard<br/>server.py + dashboard_live.html]
        LOG[(logs/predictions.jsonl)]

        SNORT --> MON --> PRED
        PRED --> OUT1
        PRED --> OUT2
        PRED --> LOG
    end

    MD -.->|load trained weights| PRED
```

### Training pipeline (detailed)

```mermaid
flowchart LR
    subgraph INPUT
        TRAIN[UNSW_NB15_training-set.csv]
        TEST[UNSW_NB15_testing-set.csv]
    end

    subgraph PREP
        A1[Drop id column]
        A2[Extract binary + attack_cat labels]
        A3[Fill missing values<br/>training medians only]
        A4[One-hot encode<br/>proto · service · state]
        A5[StandardScaler fit on train]
    end

    subgraph MODELS
        B1[SMOTE on training set]
        B2[ANN — supervised<br/>Dense layers · sigmoid]
        B3[Autoencoder — unsupervised<br/>Encoder → bottleneck → Decoder]
    end

    subgraph OUTPUT
        C1[ann_model.h5]
        C2[autoencoder_model.h5]
        C3[autoencoder_model_threshold.npy]
        C4[scaler_params.npy · feature_columns.npy]
        C5[Reports · confusion matrices · plots]
    end

    TRAIN --> A1 --> A2 --> A3 --> A4 --> A5
    TEST  --> A3
    A5 --> B1 --> B2
    A5 --> B3
    B2 --> C1
    B3 --> C2
    B3 --> C3
    A5 --> C4
    B2 --> C5
    B3 --> C5
```

| Step | Module | Output |
|---|---|---|
| Load | `load_data.py` | Raw train/test DataFrames |
| Preprocess | `preprocess.py` | Scaled feature matrices, labels |
| Balance | `smote_processing.py` | SMOTE-resampled training set (ANN only) |
| Train ANN | `ann_model.py` | Binary attack classifier |
| Train AE | `autoencoder_model.py` | Anomaly detector + MSE threshold |
| Evaluate | `evaluate.py` | Metrics, reports, comparison plots |

### Real-time detection pipeline (detailed)

```mermaid
flowchart TB
    subgraph CAPTURE["Alert ingestion — snort_monitor.py"]
        MODE{Mode?}
        SIM[Simulate loop<br/>realistic alert templates]
        LIVE[Live Snort process<br/>snort.exe -i interface]
        Q[(Alert queue)]

        MODE -->|simulate=True| SIM --> Q
        MODE -->|simulate=False| LIVE --> Q
    end

    subgraph ALERT["Parsed alert fields"]
        F1[timestamp · src/dst IP · ports]
        F2[protocol · message · priority]
        F3[category · rule ID]
    end

    subgraph ENGINE["Decision engine — ai_predictor.py"]
        S1[Step 1 — Snort-primary verdict]
        S2[Step 2 — AI informational scores]
        VEC[Build approximate<br/>194-dim feature vector]
        ANN_R[ANN inference<br/>confidence score]
        AE_R[Autoencoder inference<br/>reconstruction MSE]

        S1 --> VERDICT{Final verdict}
        Q --> ALERT --> S1
        ALERT --> VEC --> ANN_R
        VEC --> AE_R
        ANN_R --> S2
        AE_R --> S2
        S2 --> VERDICT
    end

    subgraph PRESENT["Output"]
        CLI[Terminal rows — main.py]
        WEB[SocketIO events — server.py]
        JSONL[predictions.jsonl]
    end

    VERDICT --> CLI
    VERDICT --> WEB
    VERDICT --> JSONL
```

### Detection decision logic

The **authoritative verdict** comes from Snort rule priority and message. ANN and Autoencoder scores are computed and shown on the dashboard as **informational confidence indicators** — they do not override the Snort verdict.

```mermaid
flowchart TD
    A[Snort alert received] --> B{Priority?}

    B -->|Priority 1| C[ATTACK<br/>High severity — e.g. SYN flood, SQL injection]
    B -->|Priority 2| D[ATTACK<br/>Medium severity — e.g. port scan, DNS amplify]
    B -->|Priority 3| E{Message type?}

    E -->|ICMP ping · Telnet connection| F[NORMAL<br/>Informational traffic]
    E -->|Any other message| G[ATTACK<br/>Unexpected alert]

    C --> H[Run ANN + AE for scores]
    D --> H
    F --> H
    G --> H

    H --> I[Emit verdict + ann_conf + ae_mse]
```

| Priority | Examples | Verdict |
|---|---|---|
| 1 | SYN flood, SQL injection, brute force | Always **ATTACK** |
| 2 | Port scan, DNS amplification, XSS | Always **ATTACK** |
| 3 | ICMP ping, Telnet connection | **NORMAL** |
| 3 | Other messages | **ATTACK** |

### Web dashboard architecture

```mermaid
flowchart LR
    subgraph CLIENT["Browser"]
        HTML[dashboard_live.html]
        WS[SocketIO client]
        HTML --- WS
    end

    subgraph SERVER["server.py"]
        FLASK[Flask HTTP :5000]
        SIO[Flask-SocketIO]
        LOOP[Monitor thread<br/>_loop]
        PRED2[AIPredictor]
        MON2[SnortMonitor]

        FLASK -->|GET /| HTML
        SIO <-->|WebSocket| WS
        SIO -->|start_monitor · stop_monitor| LOOP
        LOOP --> MON2 --> PRED2
        PRED2 -->|new_alert · terminal · system_status| SIO
    end

    subgraph EVENTS["SocketIO events"]
        E1[connect → system_status]
        E2[start_monitor → monitor_started]
        E3[new_alert → alert card + stats]
        E4[terminal → live log lines]
    end

    SIO --- EVENTS
```

| Component | Role |
|---|---|
| `Flask` | Serves dashboard HTML at `/` and status JSON at `/status` |
| `Flask-SocketIO` | Bi-directional real-time events between browser and server |
| `SnortMonitor` | Background thread feeding alerts into the prediction loop |
| `AIPredictor` | Loads saved models and produces verdict + scores per alert |
| `dashboard_live.html` | Live alert feed, attack counters, and terminal log |

### Component interaction map

```mermaid
flowchart TB
    main[main.py]
    server[server.py]

    main --> load_data
    main --> preprocess
    main --> smote_processing
    main --> ann_model
    main --> autoencoder_model
    main --> evaluate
    main --> snort_monitor
    main --> ai_predictor

    server --> snort_monitor
    server --> ai_predictor
    server --> ann_model
    server --> autoencoder_model
    server --> dashboard_live[dashboard_live.html]

    ai_predictor --> ann_model
    ai_predictor --> autoencoder_model

    snort_monitor --> snort_rules[snort_rules/local.rules]
```

## Project structure

```
ai_based_ids_system/
├── main.py                 # Train, evaluate, and run CLI monitor
├── server.py               # Web dashboard server
├── dashboard_live.html     # Live dashboard UI
├── requirements.txt        # Python dependencies
├── DATASET.md              # Dataset download and citation info
├── src/
│   ├── load_data.py        # Load UNSW-NB15 CSVs
│   ├── preprocess.py       # Feature scaling and encoding
│   ├── smote_processing.py # SMOTE oversampling
│   ├── ann_model.py        # ANN training and inference
│   ├── autoencoder_model.py# Autoencoder training and inference
│   ├── ai_predictor.py     # Combined ANN + AE predictor
│   ├── evaluate.py         # Metrics, reports, and plots
│   └── snort_monitor.py    # Snort alert ingestion
├── data/                   # Place dataset CSVs here (not in repo)
├── models/                 # Saved models after training
├── results/                # Evaluation reports and plots
├── logs/                   # Runtime prediction logs
└── snort_rules/            # Snort rule files
```

## Prerequisites

- Python 3.10+
- pip

Optional for live monitoring:

- Snort installed and configured
- Administrator privileges (for live network capture)

## Setup

### 1. Clone the repository

```bash
git clone <your-repo-url>
cd ai_based_ids_system
```

### 2. Create a virtual environment

```bash
python -m venv ids
ids\Scripts\activate        # Windows
# source ids/bin/activate   # Linux/macOS
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Download the dataset

The UNSW-NB15 CSV files are not included in this repo. See [DATASET.md](DATASET.md) for download links, licensing terms, and citation requirements.

Place these files in `data/`:

- `UNSW_NB15_training-set.csv`
- `UNSW_NB15_testing-set.csv`

## Usage

### Train and evaluate

```bash
python main.py --no-monitor
```

This runs the full pipeline: load data → preprocess → SMOTE → train ANN and Autoencoder → evaluate → save models to `models/` and reports to `results/`.

### Train and monitor (CLI)

```bash
python main.py                  # simulated Snort alerts
python main.py --live --iface 5 # live Snort on network interface 5
```

### Monitor only (models already trained)

```bash
python main.py --skip-training
```

### Web dashboard

```bash
python server.py                # opens http://127.0.0.1:5000
python server.py --live --iface 5
python server.py --port 8080 --no-open
```

Train models first if they do not exist:

```bash
python main.py --no-monitor
python server.py
```

## How detection works

1. **Snort** raises an alert (live capture or simulation).
2. **`snort_monitor.py`** parses it into structured fields (IP, port, protocol, priority, message).
3. **`ai_predictor.py`** applies Snort-primary rules to set the final verdict.
4. ANN and Autoencoder run in parallel to produce **confidence** and **MSE** scores for the dashboard.
5. Results go to the CLI, web dashboard, and `logs/predictions.jsonl`.

| Component | Role in detection |
|---|---|
| Snort rules | **Primary** — priority + message determine ATTACK / NORMAL |
| ANN | **Secondary** — confidence score (informational) |
| Autoencoder | **Secondary** — reconstruction MSE (informational) |

| Model | Trained on | Used for |
|---|---|---|
| ANN | SMOTE-balanced training data | Confidence display on dashboard |
| Autoencoder | Normal traffic only | MSE display on dashboard |

See the [Detection decision logic](#detection-decision-logic) diagram above for the full verdict flow.

## Output

After training, check:

| Location | Contents |
|---|---|
| `models/` | `ann_model.h5`, `autoencoder_model.h5`, scaler and feature files |
| `results/` | Text reports, confusion matrices, learning curves |
| `logs/predictions.jsonl` | Real-time prediction log (created during monitoring) |

## License

**Code in this repository:** Your choice — add a `LICENSE` file if you plan to open-source it.

**UNSW-NB15 dataset:** Academic use is permitted by the original authors. Commercial use requires their permission. See [DATASET.md](DATASET.md) for full terms and required citations.
