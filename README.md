# A Multi-Layer Risk Assessment Framework for Mitigating Social Engineering Attacks

This project implements a Streamlit-based research prototype for assessing social engineering risk across three independent layers:

1. Human Layer
2. Technical Layer
3. Organizational Layer

The framework generates:
- Risk Score
- Risk Level
- NIST-aligned recommendations
- Optional phishing URL feature analysis

## Hidden Admin Statistics

Assessment outputs are saved automatically in:

```text
assessment_results.csv
```

Users do not see the statistics. The admin panel is available through the sidebar using the password defined inside `app.py`.

Default password:

```text
admin123
```

Change it before deployment.

## How to Run Locally

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Run the application:

```bash
python -m streamlit run app.py
```

## Deployment Note

This CSV-based storage is suitable for a fast research prototype. For long-term public deployment, use a persistent external storage option such as Google Sheets, Firebase, Supabase, or a database service.
