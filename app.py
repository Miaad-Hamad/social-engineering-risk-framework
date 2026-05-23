import streamlit as st
import math
import re
import os
import pandas as pd
from datetime import datetime
from urllib.parse import urlparse

st.set_page_config(
    page_title="A Multi-Layer Risk Assessment Framework",
    page_icon="🛡️",
    layout="centered"
)

RESULTS_FILE = "assessment_results.csv"
ADMIN_PASSWORD = "admin987987"  # Change this password before deployment.

OPTIONS = {
    "Strongly Implemented": 4,
    "Mostly Implemented": 3,
    "Partially Implemented": 2,
    "Weakly Implemented": 1,
    "Not Implemented": 0
}

st.title("🛡️ A Multi-Layer Risk Assessment Framework")
st.write(
    "A framework for mitigating social engineering attacks by assessing Human, "
    "Technical, and Organizational risk layers."
)

def calculate_risk_score(scores):
    max_score = len(scores) * 4
    achieved_score = sum(scores)
    maturity_percentage = (achieved_score / max_score) * 100
    risk_score = 100 - maturity_percentage
    return round(risk_score, 2)

def classify_risk(score):
    if score <= 33:
        return "Low Risk", "🟢"
    elif score <= 66:
        return "Medium Risk", "🟠"
    else:
        return "High Risk", "🔴"

def save_result(layer_name, risk_score, risk_level):
    new_result = {
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Layer": layer_name,
        "Risk Score": risk_score,
        "Risk Level": risk_level
    }

    if os.path.exists(RESULTS_FILE):
        df = pd.read_csv(RESULTS_FILE)
        df = pd.concat([df, pd.DataFrame([new_result])], ignore_index=True)
    else:
        df = pd.DataFrame([new_result])

    df.to_csv(RESULTS_FILE, index=False)

def show_results(layer_name, scores, recommendations):
    risk_score = calculate_risk_score(scores)
    risk_level, icon = classify_risk(risk_score)

    save_result(layer_name, risk_score, risk_level)

    st.subheader(f"{icon} {layer_name} Result")
    st.metric("Risk Score", f"{risk_score}%")
    st.write(f"**Risk Level:** {risk_level}")

    st.subheader("NIST-Aligned Recommendations")
    for rec in recommendations[risk_level]:
        st.write(f"- {rec}")

    st.success("Assessment completed successfully.")

def ask_questions(questions):
    scores = []
    for q in questions:
        answer = st.radio(q, list(OPTIONS.keys()), key=q)
        scores.append(OPTIONS[answer])
    return scores

def calculate_entropy(text):
    if not text:
        return 0
    probability = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probability)

def analyze_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    query = parsed.query

    features = {
        "url_length": len(url),
        "has_ip_address": bool(re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", url)),
        "dot_count": url.count("."),
        "https_flag": url.startswith("https://"),
        "url_entropy": round(calculate_entropy(url), 2),
        "token_count": len(re.split(r"[\/\-\_\?\=\&\.]", url)),
        "subdomain_count": max(domain.count(".") - 1, 0),
        "query_param_count": query.count("="),
        "path_length": len(path),
        "has_hyphen_in_domain": "-" in domain,
        "number_of_digits": sum(c.isdigit() for c in url),
        "suspicious_file_extension": bool(re.search(r"\.(exe|zip|scr|bat|js|apk|rar)$", path.lower())),
        "percentage_numeric_chars": round((sum(c.isdigit() for c in url) / len(url)) * 100, 2) if url else 0
    }

    risk_points = 0
    if features["url_length"] > 75:
        risk_points += 1
    if features["has_ip_address"]:
        risk_points += 1
    if features["dot_count"] > 4:
        risk_points += 1
    if not features["https_flag"]:
        risk_points += 1
    if features["url_entropy"] > 4.5:
        risk_points += 1
    if features["token_count"] > 12:
        risk_points += 1
    if features["subdomain_count"] > 2:
        risk_points += 1
    if features["query_param_count"] > 3:
        risk_points += 1
    if features["has_hyphen_in_domain"]:
        risk_points += 1
    if features["percentage_numeric_chars"] > 15:
        risk_points += 1
    if features["suspicious_file_extension"]:
        risk_points += 1

    url_risk_score = round((risk_points / 11) * 100, 2)
    return features, url_risk_score

human_questions = [
    "Does the organization provide regular cybersecurity awareness training to employees?",
    "Are employees trained to recognize social engineering attacks such as phishing?",
    "Is cybersecurity awareness training mandatory for all staff members?",
    "Are cybersecurity responsibilities clearly defined for employees in their job descriptions?",
    "Do employees understand their role in protecting organizational information assets?",
    "Are employees required to acknowledge and comply with cybersecurity policies?",
    "Does the organization enforce accountability for violations of cybersecurity policies?",
    "Do employees have a clear process to report suspicious activities or security incidents?",
    "Are employees encouraged to report cybersecurity incidents without fear of punishment?",
    "Does the organization have awareness programs addressing insider threats?"
]

technical_questions = [
    "Does the organization implement technical access controls to restrict system access to authorized users only?",
    "Are strong authentication mechanisms, such as MFA, implemented for critical systems?",
    "Is sensitive data protected using encryption at rest and in transit?",
    "Are system activities and security events logged and monitored continuously?",
    "What is the organization’s capability to detect suspicious URL characteristics, such as abnormal length, deceptive subdomains, unusual token patterns, and malicious query structures associated with phishing attacks?",
    "Are systems regularly scanned for vulnerabilities and updated with security patches?",
    "Are secure backup systems implemented and tested to ensure data recovery?",
    "Are networks protected using security mechanisms such as firewalls and segmentation?",
    "Are systems configured securely based on established security baselines?",
    "Are technical tools and systems in place to support incident response and containment?"
]

organizational_questions = [
    "Does the organization have a defined cybersecurity governance structure approved by senior management?",
    "Is there a documented cybersecurity strategy aligned with business objectives?",
    "Are cybersecurity roles, responsibilities, and accountability formally defined at the organizational level?",
    "Does the organization have a formal enterprise risk management process for cybersecurity?",
    "Are cybersecurity risks reviewed and updated at a regular organizational level?",
    "Does the organization maintain formally documented cybersecurity policies?",
    "Are cybersecurity policies reviewed and approved by executive management on a regular basis?",
    "Is there a structured process for developing and updating security policies across the organization?",
    "Does the organization have a formal process to ensure compliance with cybersecurity laws and regulations?",
    "Does the organization conduct regular management reviews of its cybersecurity governance and risk posture?"
]

human_recommendations = {
    "Low Risk": [
        "Maintain regular cybersecurity awareness training.",
        "Continue reinforcing phishing reporting procedures.",
        "Periodically evaluate employee awareness effectiveness."
    ],
    "Medium Risk": [
        "Increase the frequency of cybersecurity awareness training.",
        "Improve phishing recognition exercises and reporting simulations.",
        "Strengthen accountability and policy acknowledgment processes."
    ],
    "High Risk": [
        "Implement mandatory cybersecurity awareness and phishing training.",
        "Establish a clear and safe incident reporting process.",
        "Define employee cybersecurity responsibilities and enforce policy compliance."
    ]
}

technical_recommendations = {
    "Low Risk": [
        "Maintain continuous monitoring and periodic technical assessments.",
        "Continue updating phishing detection mechanisms and security controls.",
        "Regularly validate backup, logging, and incident response capabilities."
    ],
    "Medium Risk": [
        "Improve monitoring and logging for URL-related and security events.",
        "Enhance detection of suspicious URL characteristics and phishing indicators.",
        "Review MFA coverage, vulnerability scanning, patching, and secure configuration practices."
    ],
    "High Risk": [
        "Implement automated phishing URL analysis and filtering mechanisms.",
        "Enforce MFA across all critical systems and access points.",
        "Strengthen continuous monitoring, logging, and anomaly detection.",
        "Apply encryption, secure configuration baselines, and regular vulnerability management.",
        "Improve incident response and containment capabilities."
    ]
}

organizational_recommendations = {
    "Low Risk": [
        "Maintain periodic governance and policy reviews.",
        "Continue monitoring compliance with cybersecurity policies.",
        "Keep risk management practices aligned with organizational objectives."
    ],
    "Medium Risk": [
        "Improve cybersecurity governance oversight and management reviews.",
        "Strengthen policy enforcement and compliance tracking.",
        "Update risk management processes and align policies with business objectives."
    ],
    "High Risk": [
        "Establish a formal cybersecurity governance structure.",
        "Develop and approve documented cybersecurity policies and strategy.",
        "Define organizational roles, responsibilities, and accountability.",
        "Implement a formal cybersecurity risk management and compliance process."
    ]
}

layer = st.selectbox(
    "Select the layer you want to assess:",
    ["Human Layer", "Technical Layer", "Organizational Layer"]
)

if layer == "Human Layer":
    st.header("Human Layer Assessment")
    scores = ask_questions(human_questions)
    if st.button("Calculate Human Risk"):
        show_results("Human Layer", scores, human_recommendations)

elif layer == "Technical Layer":
    st.header("Technical Layer Assessment")
    scores = ask_questions(technical_questions)

    if st.button("Calculate Technical Risk"):
        show_results("Technical Layer", scores, technical_recommendations)

    st.divider()
    st.subheader("Phishing URL Feature Analysis")
    url = st.text_input("Enter a URL to analyze based on phishing-related URL features:")

    if st.button("Analyze URL"):
        if url:
            features, url_risk = analyze_url(url)
            st.write("**Extracted URL Features:**")
            st.dataframe(pd.DataFrame([features]), use_container_width=True)

            url_level, url_icon = classify_risk(url_risk)
            st.metric("URL Risk Score", f"{url_risk}%")
            st.write(f"**URL Risk Level:** {url_icon} {url_level}")
        else:
            st.warning("Please enter a URL before analysis.")

elif layer == "Organizational Layer":
    st.header("Organizational Layer Assessment")
    scores = ask_questions(organizational_questions)
    if st.button("Calculate Organizational Risk"):
        show_results("Organizational Layer", scores, organizational_recommendations)

st.sidebar.divider()
st.sidebar.subheader("Admin Panel")
admin_password = st.sidebar.text_input("Admin password", type="password")

if admin_password == ADMIN_PASSWORD:
    st.sidebar.success("Admin access granted.")
    st.subheader("Admin Statistics")

    if os.path.exists(RESULTS_FILE):
        results_df = pd.read_csv(RESULTS_FILE)

        st.write("Saved Assessment Results")
        st.dataframe(results_df, use_container_width=True)

        if not results_df.empty:
            avg_scores = results_df.groupby("Layer", as_index=False)["Risk Score"].mean()
            st.write("Average Risk Score by Layer")
            st.bar_chart(avg_scores, x="Layer", y="Risk Score")

            risk_counts = results_df["Risk Level"].value_counts().reset_index()
            risk_counts.columns = ["Risk Level", "Count"]
            st.write("Risk Level Distribution")
            st.dataframe(risk_counts, use_container_width=True)

            csv_data = results_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="Download Assessment Results as CSV",
                data=csv_data,
                file_name="assessment_results.csv",
                mime="text/csv"
            )
        else:
            st.info("No saved results yet.")
    else:
        st.info("No assessment results saved yet.")

elif admin_password:
    st.sidebar.error("Invalid admin password.")

st.caption(
    "Recommendations are aligned with NIST Cybersecurity Framework principles and NIST SP 800-50 awareness and training guidance."
)
