# Network Guard AI

*⚠️ Under Active Development — evolving toward a production-ready Network Intrusion Detection System (NIDS)*

## Overview

**Network Guard AI** is an AI-powered network intrusion detection system built with machine learning. It monitors network traffic in (near) real time and flags malicious activities such as DDoS, port scanning, SQL injection, brute force attacks, and other anomalies.

The models are primarily trained on the **CIC-IDS2017** dataset, and enriched using Kaggle’s SQL injection dataset to improve detection across multiple attack types.

---

## Features

* **AI-based Detection:** Multi-class classification of network intrusions (DoS, DDoS, PortScan, Brute Force, SQL Injection, etc.)
* **Real-time inference** on network flow data
* **Modular architecture** to easily extend datasets and attack classes
* **Testing suite** for reliability and correctness
* **Jupyter notebooks** for experiments and benchmarking

---

## Repository Structure

```
.
├── data/                   # Raw and processed datasets  
├── notebooks/              # Jupyter notebooks for experiments  
├── service/                # Service / inference engine code  
└── test/                   # Unit / integration tests  
```

---

## Getting Started

### Prerequisites

* Python 3.8+
* (Optional) GPU for training
* Required Python packages:

```bash
pip install -r requirements.txt
```

### Running Experiments / Training

1. Place the **CIC-IDS2017** dataset (and optional SQL injection data) in the `data/` folder.
2. Run preprocessing scripts to convert raw logs/flows into model-ready features.
3. Use the `notebooks/` directory for training and evaluation.
4. Save trained model artifacts for deployment.

---

## Download Pre-trained Models (Hugging Face Private Repo)

To run the APIs, you must download the pre-trained models from **[To be Uploaded Hugging Face private repositories]**.

### Steps

1. **Create a Hugging Face account** if you don’t already have one.
2. **Request access** to the private model repository (via email or GitHub instructions).
3. **Accept the invite** from Hugging Face.
4. **Download the model** using either:

   * `transformers` for **DistilBERT-based models**, or
   * `joblib` for **CICFlowMeter-based models**.

Example:

```python
from transformers import AutoModel, AutoTokenizer
import joblib

# DistilBERT (text-based intrusion detection)
tokenizer = AutoTokenizer.from_pretrained("huggingface-username/distilbert_sql")
model = AutoModel.from_pretrained("huggingface-username/distilbert_sql")

# CICFlowMeter (network-flow-based model)
model = joblib.load("path/to/cicflowmeter.joblib")
```

---

## Evaluation Metrics

Evaluation notebooks include:

* Accuracy, Precision, Recall, F1-Score
* ROC / AUC curves
* Confusion matrices
* False positive rate

Future work may also include:

* Latency and throughput benchmarks
* Real-time performance profiling

---

## Roadmap

* Real-time streaming inference engine
* Visualization dashboard and alerting system
* Benchmark system performance

---

## Contributing

Contributions are welcome!
You can help by:

* Submitting bug fixes or enhancements
* Improving documentation or notebooks
* Writing tests or optimizing inference

Please ensure code style consistency and include test coverage for new features.

---

## License & Contact

* **Author:** Rayen Nait Slimane
* **Contact:** [rayennaitslimane@gmail.com](mailto:rayennaitslimane@gmail.com)
