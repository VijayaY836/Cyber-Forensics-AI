# 🔍 AI-Based Log Investigation Framework for Next-Generation Cyber Forensics

## 🎯 Project Overview
An autonomous forensic analyst that uses Machine Learning to detect, correlate, and explain cyber attacks from system logs.

## 🚀 Features
- **Automated Log Ingestion**: CSV and JSON support
- **AI-Powered Anomaly Detection**: Isolation Forest algorithm
- **Attack Chain Correlation**: Graph-based event linking
- **Timeline Reconstruction**: Chronological attack visualization
- **Explainable Reports**: Auto-generated forensic analysis
- **SOC-Style Dashboard**: Dark theme, professional UI

## 🛠️ Tech Stack
- **Frontend**: Streamlit
- **Backend**: Python
- **ML**: scikit-learn (Isolation Forest)
- **Data Processing**: Pandas
- **Graph Analysis**: NetworkX
- **Visualization**: Plotly

## 📦 Installation

### 1. Clone the Repository
```bash
git clone <your-repo-url>
cd cyber-forensics-ai
```

### 2. Create Virtual Environment
```bash
python -m venv venv
```

### 3. Activate Virtual Environment
**Windows:**
```bash
venv\Scripts\activate
```

**Mac/Linux:**
```bash
source venv/bin/activate
```

### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

## 🎮 How to Run

```bash
streamlit run app.py
```

The dashboard will open in your browser at `http://localhost:8501`

## 📁 Project Structure
```
cyber-forensics-ai/
├── app.py                      # Main Streamlit application
├── requirements.txt            # Dependencies
├── data/                       # Sample log files
├── modules/                    # Core logic
│   ├── log_parser.py
│   ├── anomaly_detector.py
│   ├── event_correlator.py
│   ├── timeline_builder.py
│   └── report_generator.py
├── utils/                      # Helper functions
│   └── visualization.py
└── assets/                     # UI styling
    └── style.css
```

## 🎓 Created for [Hackathon Name]
**Team**: InnovaTech
**Date**: December 2025