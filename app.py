import streamlit as st
import pandas as pd
import joblib
import matplotlib.pyplot as plt

# -----------------------------
# Page Configuration
# -----------------------------

st.set_page_config(
    page_title="Network Intrusion Detection",
    page_icon="🛡️",
    layout="wide"
)

# -----------------------------
# Hacker Theme CSS
# -----------------------------

st.markdown("""
<style>

/* Main background */
.stApp{
background-color:#0b0f19;
color:#00ff9c;
}

/* Text */
h1,h2,h3,h4,h5,p,label{
color:#00ff9c !important;
}

/* Sidebar */
section[data-testid="stSidebar"]{
background-color:#111827;
}

/* Button default */
div.stButton > button{
background-color:#1f2937;
color:#00ff9c;
font-weight:700;
border-radius:10px;
border:1px solid #00ff9c;
padding:10px 20px;
transition:0.3s;
}

/* Neon hover */
div.stButton > button:hover{
background-color:#00ff9c;
color:#28282b !important;
font-weight:700;
box-shadow:0 0 5px #00ff9c;
}

</style>
""", unsafe_allow_html=True)

# -----------------------------
# Load Model & Data
# -----------------------------

model = joblib.load("random_forest_model.pkl")
sample = pd.read_csv("demo_sample.csv")

features = sample.columns

# -----------------------------
# Header
# -----------------------------

st.title("🛡️ AI Network Intrusion Detection Dashboard")

st.markdown(
"""
Real-time **Machine Learning Network Threat Detection Dashboard**

Model: Random Forest  
Dataset: UNSW-NB15
"""
)

# -----------------------------
# Metrics
# -----------------------------

col1,col2,col3 = st.columns(3)

col1.metric("Model Accuracy","87.2%")
col2.metric("Features Used",len(features))
col3.metric("Algorithms Tested","4")

st.markdown("---")

# -----------------------------
# Sidebar
# -----------------------------

st.sidebar.title("📂 Upload Network Data")

uploaded_file = st.sidebar.file_uploader(
    "Upload CSV File",
    type=["csv"]
)

# Dataset Requirements Toggle

st.sidebar.markdown("---")

if st.sidebar.checkbox("Show Dataset Requirements"):

    st.sidebar.markdown("### Required Dataset Structure")

    st.sidebar.markdown("""
Your CSV must contain **42 network traffic features** used by the machine learning model.

Each row represents **one network connection record captured from network traffic**.

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
""")

# -----------------------------
# Data Source Logic
# -----------------------------

if uploaded_file is not None:

    input_df = pd.read_csv(uploaded_file)
    data_source = uploaded_file.name

else:

    input_df = sample.copy()
    data_source = "demo_sample.csv"

# Ensure correct feature order
input_df = input_df[features]

# -----------------------------
# Packet Data Toggle
# -----------------------------

if st.checkbox("Show Packet Feature Data Used For Testing"):

    st.subheader(f"Packet Data Source: {data_source}")

    st.dataframe(input_df, use_container_width=True)

# -----------------------------
# Detection Section
# -----------------------------

st.markdown("---")
st.subheader("Threat Analysis")

if st.button("🚀 Run Intrusion Detection"):

    prediction = model.predict(input_df)[0]
    probability = model.predict_proba(input_df)[0]

    confidence = max(probability)*100

    st.markdown("## Detection Result")

    if prediction == 1:
        st.error("🚨 MALICIOUS NETWORK ATTACK DETECTED")
    else:
        st.success("✅ NETWORK TRAFFIC IS SAFE")

    # Metrics

    col1,col2,col3 = st.columns(3)

    col1.metric("Detection Confidence",f"{confidence:.2f}%")
    col2.metric("Model Accuracy","87.2%")
    col3.metric("Data Source",data_source)

    st.progress(confidence/100)

    st.markdown("---")

    # -----------------------------
    # Charts Layout
    # -----------------------------

    chart1,chart2 = st.columns(2)

    # Attack Probability Chart

    with chart1:

        st.subheader("Attack Probability")

        labels=["Safe Traffic","Attack Traffic"]
        values=probability

        fig,ax=plt.subplots()

        fig.patch.set_facecolor("#0b0f19")
        ax.set_facecolor("#0b0f19")

        ax.bar(labels,values,color="#00ff9c")

        ax.tick_params(colors="#00ff9c")
        ax.set_ylabel("Probability",color="#00ff9c")
        ax.set_title("Threat Probability",color="#00ff9c")

        for spine in ax.spines.values():
            spine.set_color("#00ff9c")

        st.pyplot(fig)

    # Feature Importance Chart

    with chart2:

        st.subheader("Top Detection Features")

        importances=model.feature_importances_

        importance_df=pd.DataFrame({
            "Feature":features,
            "Importance":importances
        }).sort_values(by="Importance",ascending=False).head(10)

        fig2,ax2=plt.subplots()

        fig2.patch.set_facecolor("#0b0f19")
        ax2.set_facecolor("#0b0f19")

        ax2.barh(
            importance_df["Feature"],
            importance_df["Importance"],
            color="#00ff9c"
        )

        ax2.tick_params(colors="#00ff9c")
        ax2.set_title("Feature Importance",color="#00ff9c")

        for spine in ax2.spines.values():
            spine.set_color("#00ff9c")

        st.pyplot(fig2)

# -----------------------------
# Footer
# -----------------------------

st.markdown("---")

st.markdown(
"""
Cybersecurity AI Dashboard

Machine Learning Models Tested:
- Random Forest
- Gradient Boosting
- K-Nearest Neighbors
- Decision Tree
"""
)
