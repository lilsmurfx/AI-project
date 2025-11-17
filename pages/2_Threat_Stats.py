import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timezone

# ----------------------------------------------------
# PAGE CONFIG – clean, centered dashboard layout
# ----------------------------------------------------
st.set_page_config(
    page_title="Threat Stats",
    page_icon="📊",
    layout="wide"
)

st.title("📊 Threat Analytics Dashboard")
st.markdown("### Cyber Threat Trends & Live Detection Insights")
st.markdown("---")


# ----------------------------------------------------
# SAFE LOG LOADING
# ----------------------------------------------------
try:
    logs = pd.read_csv("logs/scans.csv")
    required_cols = {"timestamp", "url", "label", "score"}
    if not required_cols.issubset(logs.columns):
        raise ValueError("Malformed logs file")
except Exception:
    logs = pd.DataFrame({"timestamp": [], "url": [], "label": [], "score": []})


# ----------------------------------------------------
# TIMESTAMP PARSING
# ----------------------------------------------------
if not logs.empty:
    logs["timestamp"] = pd.to_datetime(
        logs["timestamp"], utc=True, errors="coerce"
    )
    logs = logs.dropna(subset=["timestamp"])


# ----------------------------------------------------
# KPI METRIC CARDS
# ----------------------------------------------------
safe_count = int((logs["label"] == 0).sum())
malicious_count = int((logs["label"] == 1).sum())
total_scans = safe_count + malicious_count

col1, col2, col3 = st.columns(3)

col1.metric(
    label="Total Scans",
    value=f"{total_scans:,}",
    delta="↑ Active Monitoring"
)

col2.metric(
    label="Safe Websites",
    value=f"{safe_count:,}",
    delta=f"{(safe_count / total_scans * 100) if total_scans else 0:.1f}% safe"
)

col3.metric(
    label="Malicious Detected",
    value=f"{malicious_count:,}",
    delta=f"{(malicious_count / total_scans * 100) if total_scans else 0:.1f}% risk",
)


st.markdown("---")


# ----------------------------------------------------
# PIE CHART SECTION
# ----------------------------------------------------
st.subheader("Threat Category Distribution")

if logs.empty:
    sample = pd.DataFrame({
        "Category": ["Safe", "Suspicious", "Malicious"],
        "Count": [120, 35, 22]
    })
    fig = px.pie(sample, names="Category", values="Count", hole=0.4)
else:
    agg = logs["label"].value_counts().rename_axis("label").reset_index(name="Count")
    agg["label"] = agg["label"].map({0: "Safe", 1: "Malicious"}).fillna("Unknown")
    fig = px.pie(agg, names="label", values="Count", hole=0.4)

fig.update_layout(
    showlegend=True,
    margin=dict(l=20, r=20, t=40, b=20)
)
st.plotly_chart(fig, use_container_width=True)

st.markdown("---")


# ----------------------------------------------------
# RECENT SCANS TABLE (Styled)
# ----------------------------------------------------
st.subheader("Recent Scan Activity")

if logs.empty:
    st.info("No scans yet. Run a scan in the Analyzer.")
else:
    recent = logs.sort_values("timestamp", ascending=False).head(50)
    st.dataframe(
        recent.style.highlight_min(subset=["label"], color="#ffcccc"),
        use_container_width=True
    )


# ----------------------------------------------------
# LAST UPDATED FOOTER
# ----------------------------------------------------
st.caption(
    f"Last updated: **{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}**"
)
