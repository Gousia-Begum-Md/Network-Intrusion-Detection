import streamlit as st
import pandas as pd
import joblib
import time
import matplotlib.pyplot as plt
import numpy as np

st.set_page_config(layout="wide")

# Hide the Streamlit header and footer using CSS
hide_style = """
    <style>
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    </style>
    """
st.markdown(hide_style, unsafe_allow_html=True)

# --- 1. INITIALIZATION ---
if 'page' not in st.session_state:
    st.session_state.page = "Home"
if 'analyzed_data' not in st.session_state:
    st.session_state.analyzed_data = None

# --- 2. UI ---
st.set_page_config(page_title="ANIDS", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.stApp { 
    background-color: #050801; 
    color: #00ff9c;
    background-image: radial-gradient(#0a2a1a 1px, transparent 1px);
    background-size: 30px 30px;
}

@keyframes glow {
    0% { text-shadow: 0 0 5px #00ff9c; opacity: 0.8; }
    50% { text-shadow: 0 0 10px #00ff9c; opacity: 1; }
    100% { text-shadow: 0 0 5px #00ff9c; opacity: 0.8; }
}

.main-title { 
    font-family: 'Courier New', monospace; 
    font-size: 3.5rem; 
    text-align: center;
    animation: glow 3s infinite;
}

section[data-testid="stSidebar"] { 
    background-color: #0a0a0a !important; 
    border-right: 2px solid #00ff9c; 
}

.stButton>button { 
    background-color: #050801; 
    color: #00ff9c; 
    border: 1px solid #00ff9c; 
    width: 100%; 
    font-weight: bold; 
    border-radius: 8px;
}
.stButton>button:hover { 
    background-color: #00ff9c !important; 
    color: #000000 !important; 
    box-shadow: 0 0 30px #00ff9c;
}

.info-card {
    border: 1px solid #00ff9c;
    padding: 20px;
    border-radius: 10px;
    background: rgba(0, 255, 156, 0.05);
}

[data-testid="stMetric"] {
    background: rgba(0,255,156,0.08);
    padding: 10px;
    border-radius: 10px;
    border: 1px solid #00ff9c;
    text-align: center;
}
</style>
""", unsafe_allow_html=True)

# --- MODEL ---
@st.cache_resource
def load_engine():
    try:
        return joblib.load('random_forest_model.pkl'), joblib.load('model_features.pkl')
    except:
        return None, None

model, features = load_engine()

def go_to(p):
    st.session_state.page = p
    st.rerun()

# --- SIDEBAR ---
with st.sidebar:
    st.markdown("<h1 style='text-align: center;'>🛡ANIDS️</h1>", unsafe_allow_html=True)
    st.write("---")
    if st.button("🏠 Home"): go_to("Home")
    if st.button("📂 Scan Data"): go_to("Upload")
    if st.button("🔍 Results"): go_to("Results")
    st.write("---")
    if st.session_state.analyzed_data is not None:
        count = len(st.session_state.analyzed_data[st.session_state.analyzed_data['PRED'] == 1])
        st.metric("PACKETS ANALYZED", count)

# --- HOME ---
if st.session_state.page == "Home":
    st.markdown("<h1 class='main-title'>AI-BASED NETWORK INTRUSION DECTION SYSTEM</h1>", unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("""
        <div class='info-card'>
        <h3>🧠 Model Intelligence</h3>
        <p>This system is powered by a Random Forest Classifier that analyzes network traffic patterns using multiple decision trees.</p>
        <p>Each packet is evaluated across trees, and the final decision is based on collective voting.</p>
        <p><b>Advantages:</b><br>
        • Handles complex network data<br>
        • Resistant to noise and anomalies<br>
        • Captures feature interactions effectively</p>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown("""
        <div class='info-card'>
        <h3>🚀 Why ANIDS?</h3>
        <ul>
            <li>Real-Time Detection</li>
            <li>Explainable Predictions</li>
            <li>Visual Threat Analysis</li>
            <li>Scalable for large datasets</li>
        </ul>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br><br>", unsafe_allow_html=True)
    center_col = st.columns([2,1,2])
    with center_col[1]:
        if st.button("INITIALIZE SYSTEM →"):
            go_to("Upload")

# --- UPLOAD ---
elif st.session_state.page == "Upload":
    st.title("📂 Data Ingestion")

    # 🔽 USER CONTROLLED DATA GUIDE
    with st.expander("ℹ️ What data should I upload?"):
        st.markdown("""
        The following are the features that are needed to be present in your CSV file, and each row represents **one network connection record captured from network traffic**.

### Feature Explanations

• **dur** – Duration of the network connection  

• **proto** – Communication protocol used (TCP, UDP, etc)

• **service** – Network service on destination (HTTP, FTP, DNS)

• **state** – Status of the connection (success, reset, etc)

• **spkts** – Packets sent from source to destination

• **dpkts** – Packets sent from destination to source

• **sbytes** – Bytes sent from source

• **dbytes** – Bytes received from destination

• **rate** – Transmission rate of packets

• **sttl** – Source Time-To-Live value

• **dttl** – Destination Time-To-Live value

• **sload** – Source bits per second

• **dload** – Destination bits per second

• **sloss** – Lost packets from source

• **dloss** – Lost packets from destination

• **sinpkt** – Time between packets from source

• **dinpkt** – Time between packets from destination

• **sjit** – Source packet jitter

• **djit** – Destination packet jitter

• **tcprtt** – TCP round trip time

• **synack** – Time between SYN and ACK packets

• **ackdat** – Time between ACK and data packet

• **ct_state_ttl** – Connections with same state and TTL

• **ct_dst_ltm** – Connections to same destination

• **ct_src_ltm** – Connections from same source

• **ct_srv_dst** – Connections to same service and destination

• **ct_srv_src** – Connections from same service and source

• **ct_dst_sport_ltm** – Destination connections with same source port

• **ct_dst_src_ltm** – Destination connections from same source

⚠️ Your dataset must contain the same features used during model training.

**Tip:** Upload clean CSV data with no missing values for best performance.
        """)

    file = st.file_uploader("Upload Network Traffic Dataset (CSV)", type="csv")

    if file:
        df = pd.read_csv(file)

        st.write("### Sampled Traffic Snapshot")
        st.write("Preview of selected network records used for threat analysis.")
        st.dataframe(df.head(10), use_container_width=True)

        if st.button("🚀 Run Intrusion Detection"):
            with st.status("Analyzing Network Patterns...", expanded=True):
                probs = model.predict_proba(df[features])
                preds = model.predict(df[features])

                df['PRED'] = preds
                df['CONF'] = np.max(probs, axis=1) * 100

                st.session_state.analyzed_data = df
                time.sleep(1.5)
                go_to("Results")

# --- RESULTS ---
elif st.session_state.page == "Results":
    st.title("🔍 Results")

    if st.session_state.analyzed_data is None:
        st.info("No data available. Please upload dataset.")
    else:
        df = st.session_state.analyzed_data
        threats = df[df['PRED'] == 1]

        if threats.empty:
            st.success("✅ No threats detected. Network is secure.")
        else:
            col1, col2 = st.columns([1,2])

            with col1:
                st.write("### Prediction Distribution Overview")
                fig, ax = plt.subplots()
                ax.pie([len(threats), len(df)-len(threats)],
                       labels=['Threat', 'Safe'],
                       autopct='%1.1f%%',
                       colors=['#ff4b4b', '#00ff9c'])
                ax.legend()
                st.pyplot(fig)

            with col2:
                # SIMPLE CONFIDENCE
                confidence = threats['CONF'].mean()
                st.metric("Model Confidence Score", f"{confidence:.2f}%")

                st.write("---")

                if threats['rate'].mean() > 5000:
                    attack = "Denial-of-Service (DoS)"
                    reason = "High packet transmission rate detected"
                    prevention = [
                        "Apply rate limiting",
                        "Enable firewall filtering",
                        "Monitor abnormal traffic spikes"
                    ]
                elif threats['sttl'].mean() > 128:
                    attack = "Reconnaissance / Probe"
                    reason = "Suspicious TTL patterns detected"
                    prevention = [
                        "Block scanning IPs",
                        "Enable IDS/IPS alerts",
                        "Monitor port scan activity"
                    ]
                else:
                    attack = "Unknown Anomaly"
                    reason = "Irregular packet behavior detected"
                    prevention = [
                        "Inspect packet payload",
                        "Enable deep packet inspection",
                        "Monitor unusual connections"
                    ]

                st.error(f"🚨 Threat Identified: {attack}")

                st.write("### Detection Reasoning")
                st.write(reason)

                st.write("### Recommended Mitigation")
                for p in prevention:
                    st.write(f"• {p}")

# --- FOOTER ---
st.markdown("---")
st.caption("ANIDS Framework | Intelligent Network Intrusion Detection System")
