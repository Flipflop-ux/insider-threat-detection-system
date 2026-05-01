"""
Insider Threat Detection Dashboard
=====================================
Built with Streamlit — powered by Isolation Forest behavioral analytics.

HOW TO RUN LOCALLY:
    pip install streamlit pandas numpy matplotlib seaborn scikit-learn
    streamlit run app.py

HOW TO DEPLOY (Streamlit Community Cloud):
    1. Push this file to your GitHub repo
    2. Go to share.streamlit.io
    3. Connect your repo and deploy
"""

import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.cm as cm
from matplotlib.patches import Patch
import seaborn as sns
import io
import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

# ── PAGE CONFIG ──────────────────────────────────────────────
st.set_page_config(
    page_title="Insider Threat Detection",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── STYLING ───────────────────────────────────────────────────
st.markdown("""
    <style>
    .metric-card {
        background-color: #1e1e2e;
        border-radius: 10px;
        padding: 20px;
        text-align: center;
    }
    .high-risk { color: #e74c3c; font-weight: bold; }
    .medium-risk { color: #f39c12; font-weight: bold; }
    .low-risk { color: #2ecc71; font-weight: bold; }

    /* Alert banner pulse animation */
    @keyframes pulse {
        0%   { box-shadow: 0 0 0 0 rgba(231, 76, 60, 0.7); }
        70%  { box-shadow: 0 0 0 12px rgba(231, 76, 60, 0); }
        100% { box-shadow: 0 0 0 0 rgba(231, 76, 60, 0); }
    }
    .alert-banner {
        background: linear-gradient(135deg, #1a0000, #2d0000);
        border: 2px solid #e74c3c;
        border-radius: 10px;
        padding: 16px 20px;
        margin-bottom: 16px;
        animation: pulse 2s infinite;
    }
    .alert-banner h3 {
        color: #e74c3c;
        margin: 0 0 8px 0;
        font-size: 16px;
        letter-spacing: 1px;
    }
    .alert-row {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin-top: 8px;
    }
    .alert-badge {
        background-color: #e74c3c;
        color: white;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 13px;
        font-weight: bold;
        font-family: monospace;
    }
    .alert-meta {
        color: #aaa;
        font-size: 12px;
        margin-top: 8px;
    }
    .warning-banner {
        background: linear-gradient(135deg, #1a1000, #2d1f00);
        border: 2px solid #f39c12;
        border-radius: 10px;
        padding: 12px 20px;
        margin-bottom: 10px;
    }
    .warning-banner h4 {
        color: #f39c12;
        margin: 0 0 6px 0;
        font-size: 14px;
    }
    .warning-badge {
        background-color: #f39c12;
        color: white;
        padding: 3px 10px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: bold;
        font-family: monospace;
        display: inline-block;
        margin: 2px;
    }
    .all-clear {
        background: linear-gradient(135deg, #001a00, #002d00);
        border: 2px solid #2ecc71;
        border-radius: 10px;
        padding: 12px 20px;
        margin-bottom: 10px;
        color: #2ecc71;
        font-weight: bold;
    }
    </style>
""", unsafe_allow_html=True)

PALETTE = {"Low": "#2ecc71", "Medium": "#f39c12", "High": "#e74c3c"}

# ── PDF REPORT GENERATOR ──────────────────────────────────────
def generate_pdf_report(user_id, user_data, df, behavioral_fig_bytes):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter,
                            rightMargin=0.75*inch, leftMargin=0.75*inch,
                            topMargin=0.75*inch, bottomMargin=0.75*inch)
    styles = getSampleStyleSheet()
    story = []

    risk_level = str(user_data.get("risk_level", "Unknown"))
    risk_score = float(user_data.get("risk_score", 0))
    risk_colors = {"High": colors.HexColor("#e74c3c"),
                   "Medium": colors.HexColor("#f39c12"),
                   "Low": colors.HexColor("#2ecc71")}
    risk_color = risk_colors.get(risk_level, colors.grey)

    # ── Title block ──
    title_style = ParagraphStyle("title", parent=styles["Title"],
                                  fontSize=18, textColor=colors.HexColor("#1a1a2e"),
                                  spaceAfter=4)
    sub_style = ParagraphStyle("sub", parent=styles["Normal"],
                                fontSize=10, textColor=colors.grey, spaceAfter=2)
    story.append(Paragraph("🔐 Insider Threat Detection System", title_style))
    story.append(Paragraph("Analyst Investigation Report", sub_style))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%B %d, %Y — %H:%M')}", sub_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1a1a2e"), spaceAfter=12))

    # ── User risk badge ──
    badge_data = [[
        Paragraph(f"<b>User ID:</b> {user_id}", styles["Normal"]),
        Paragraph(f"<b>Risk Level:</b> <font color='{risk_color.hexval() if hasattr(risk_color,'hexval') else '#000'}'>{risk_level}</font>", styles["Normal"]),
        Paragraph(f"<b>Risk Score:</b> {risk_score:.1f} / 100", styles["Normal"]),
        Paragraph(f"<b>Status:</b> {'⚠️ Flagged Anomaly' if user_data.get('is_anomaly') else 'Normal'}", styles["Normal"]),
    ]]
    badge_table = Table(badge_data, colWidths=[1.7*inch, 1.7*inch, 1.7*inch, 1.7*inch])
    badge_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8f9fa")),
        ("BOX", (0, 0), (-1, -1), 1, risk_color),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(badge_table)
    story.append(Spacer(1, 16))

    # ── Section: Behavioral Feature Summary ──
    section_style = ParagraphStyle("section", parent=styles["Heading2"],
                                    fontSize=12, textColor=colors.HexColor("#1a1a2e"),
                                    spaceBefore=12, spaceAfter=6)
    story.append(Paragraph("Behavioral Feature Summary", section_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey, spaceAfter=8))

    feature_groups = {
        "Login Behavior": ["total_logins", "off_hours_login_rate", "weekend_login_rate", "unique_pcs_used"],
        "File Access": ["total_file_events", "sensitive_file_rate", "file_deletions", "off_hours_file_rate"],
        "Email Behavior": ["total_emails", "external_email_rate", "attachment_rate", "off_hours_email_rate"],
        "Device Usage": ["usb_connections", "off_hours_usb_rate"],
    }

    for group_name, features in feature_groups.items():
        valid = [f for f in features if f in user_data.index]
        if not valid:
            continue
        story.append(Paragraph(f"<b>{group_name}</b>", styles["Normal"]))
        table_data = [["Feature", "User Value", "Population Avg", "Deviation"]]
        for feat in valid:
            val = user_data[feat]
            avg = df[feat].mean()
            dev = val - avg
            dev_str = f"+{dev:.2f}" if dev > 0 else f"{dev:.2f}"
            flag = " ⚠️" if abs(dev) > avg and "rate" in feat else ""
            table_data.append([
                feat.replace("_", " ").title(),
                f"{val:.2f}" if isinstance(val, float) else str(int(val)),
                f"{avg:.2f}",
                f"{dev_str}{flag}"
            ])
        feat_table = Table(table_data, colWidths=[2.4*inch, 1.2*inch, 1.4*inch, 1.4*inch])
        feat_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(feat_table)
        story.append(Spacer(1, 8))

    # ── Behavioral chart ──
    if behavioral_fig_bytes:
        story.append(Paragraph("Behavioral Profile vs Population Average", section_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey, spaceAfter=8))
        img = RLImage(io.BytesIO(behavioral_fig_bytes), width=6.5*inch, height=2.8*inch)
        story.append(img)
        story.append(Spacer(1, 12))

    # ── Analyst recommendation ──
    story.append(Paragraph("Analyst Recommendation", section_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey, spaceAfter=8))
    recs = {
        "High":   "⚠️ IMMEDIATE REVIEW REQUIRED — This user's behavioral profile exhibits significant deviations across multiple dimensions. Escalate to senior analyst and cross-reference with HR and access control logs.",
        "Medium": "🔍 MONITORING RECOMMENDED — This user shows moderate anomalous behavior. Schedule a review of recent activity logs within 48 hours.",
        "Low":    "✅ NO ACTION REQUIRED — This user's behavioral profile is within normal parameters. Continue passive monitoring per standard policy.",
    }
    rec_style = ParagraphStyle("rec", parent=styles["Normal"], fontSize=9,
                                backColor=colors.HexColor("#f8f9fa"),
                                borderColor=risk_color, borderWidth=1,
                                borderPadding=8, spaceAfter=8)
    story.append(Paragraph(recs.get(risk_level, "Review required."), rec_style))

    # ── Footer ──
    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey))
    footer_style = ParagraphStyle("footer", parent=styles["Normal"],
                                   fontSize=7, textColor=colors.grey, spaceAfter=2)
    story.append(Paragraph("Machine Learning-Based Insider Threat Detection System — MSIT 5910 Capstone", footer_style))
    story.append(Paragraph("⚠️ CONFIDENTIAL — For authorized security personnel only. This report is auto-generated and requires human analyst review before action.", footer_style))

    doc.build(story)
    buffer.seek(0)
    return buffer.read()

# ── SIDEBAR ───────────────────────────────────────────────────
st.sidebar.image("https://img.icons8.com/color/96/security-shield-green.png", width=80)
st.sidebar.title("🔐 Insider Threat\nDetection System")
st.sidebar.markdown("---")
st.sidebar.markdown("### Upload Data")

uploaded_file = st.sidebar.file_uploader(
    "Upload anomaly_scores.csv",
    type=["csv"],
    help="Upload the output file from your Isolation Forest pipeline"
)

st.sidebar.markdown("---")
st.sidebar.markdown("### Filters")

# ── LOAD DATA ─────────────────────────────────────────────────
@st.cache_data
def load_data(file):
    df = pd.read_csv(file)
    df = df.sort_values("risk_score", ascending=False).reset_index(drop=True)
    return df

@st.cache_data
def load_sample_data():
    """Generate sample data for demo when no file is uploaded"""
    np.random.seed(42)
    n = 500
    users = [f"U{str(i).zfill(4)}" for i in range(n)]
    
    # Normal users (475)
    normal = pd.DataFrame({
        "user": users[:475],
        "risk_score": np.random.uniform(0, 35, 475),
        "total_logins": np.random.randint(50, 200, 475),
        "off_hours_login_rate": np.random.uniform(0, 0.1, 475),
        "weekend_login_rate": np.random.uniform(0, 0.1, 475),
        "unique_pcs_used": np.random.randint(1, 3, 475),
        "total_file_events": np.random.randint(100, 500, 475),
        "sensitive_file_rate": np.random.uniform(0, 0.2, 475),
        "file_deletions": np.random.randint(0, 10, 475),
        "total_emails": np.random.randint(50, 300, 475),
        "external_email_rate": np.random.uniform(0, 0.05, 475),
        "attachment_rate": np.random.uniform(0.1, 0.3, 475),
        "usb_connections": np.random.randint(0, 5, 475),
        "off_hours_usb_rate": np.random.uniform(0, 0.1, 475),
        "off_hours_file_rate": np.random.uniform(0, 0.15, 475),
        "off_hours_email_rate": np.random.uniform(0.2, 0.35, 475),
        "is_anomaly": False,
    })
    
    # Anomalous users (25)
    anomalous = pd.DataFrame({
        "user": users[475:],
        "risk_score": np.random.uniform(70, 100, 25),
        "total_logins": np.random.randint(300, 600, 25),
        "off_hours_login_rate": np.random.uniform(0.4, 0.8, 25),
        "weekend_login_rate": np.random.uniform(0.3, 0.7, 25),
        "unique_pcs_used": np.random.randint(4, 10, 25),
        "total_file_events": np.random.randint(800, 2000, 25),
        "sensitive_file_rate": np.random.uniform(0.4, 0.9, 25),
        "file_deletions": np.random.randint(20, 80, 25),
        "total_emails": np.random.randint(400, 800, 25),
        "external_email_rate": np.random.uniform(0.3, 0.6, 25),
        "attachment_rate": np.random.uniform(0.5, 0.9, 25),
        "usb_connections": np.random.randint(15, 40, 25),
        "off_hours_usb_rate": np.random.uniform(0.3, 0.7, 25),
        "off_hours_file_rate": np.random.uniform(0.3, 0.6, 25),
        "off_hours_email_rate": np.random.uniform(0.3, 0.6, 25),
        "is_anomaly": True,
    })
    
    df = pd.concat([normal, anomalous]).sort_values("risk_score", ascending=False).reset_index(drop=True)
    df["risk_level"] = pd.cut(df["risk_score"], bins=[-1, 40, 70, 100],
                               labels=["Low", "Medium", "High"])
    return df

# Load data
if uploaded_file:
    df = load_data(uploaded_file)
    st.sidebar.success(f"✅ Loaded {len(df)} users")
else:
    df = load_sample_data()
    st.sidebar.info("📊 Using sample data — upload your anomaly_scores.csv to use real results")

# ── SIDEBAR FILTERS ───────────────────────────────────────────
risk_filter = st.sidebar.multiselect(
    "Filter by Risk Level",
    options=["High", "Medium", "Low"],
    default=["High", "Medium", "Low"]
)

score_range = st.sidebar.slider(
    "Risk Score Range",
    min_value=0, max_value=100, value=(0, 100)
)

df_filtered = df[
    (df["risk_level"].isin(risk_filter)) &
    (df["risk_score"] >= score_range[0]) &
    (df["risk_score"] <= score_range[1])
]

st.sidebar.markdown("---")
st.sidebar.markdown(f"**Showing:** {len(df_filtered)} of {len(df)} users")

# ── MAIN HEADER ───────────────────────────────────────────────
st.title("🔐 Insider Threat Detection Dashboard")
st.markdown("*Machine Learning-Based Behavioral Analytics — Isolation Forest*")
st.markdown("---")

# ── KPI METRICS ROW ───────────────────────────────────────────
col1, col2, col3, col4, col5 = st.columns(5)

total_users   = len(df)
high_risk     = len(df[df["risk_level"] == "High"])
medium_risk   = len(df[df["risk_level"] == "Medium"])
low_risk      = len(df[df["risk_level"] == "Low"])
avg_score     = df["risk_score"].mean()

with col1:
    st.metric("Total Users", total_users)
with col2:
    st.metric("🔴 High Risk", high_risk, delta=f"{high_risk/total_users*100:.1f}%")
with col3:
    st.metric("🟡 Medium Risk", medium_risk, delta=f"{medium_risk/total_users*100:.1f}%")
with col4:
    st.metric("🟢 Low Risk", low_risk, delta=f"{low_risk/total_users*100:.1f}%")
with col5:
    st.metric("Avg Risk Score", f"{avg_score:.1f}")

st.markdown("---")

# ── LIVE ALERT BANNER ─────────────────────────────────────────
high_risk_users  = df[df["risk_level"] == "High"].sort_values("risk_score", ascending=False)
med_risk_users   = df[df["risk_level"] == "Medium"].sort_values("risk_score", ascending=False)

if len(high_risk_users) > 0:
    # Build badge HTML for each high risk user
    badges_html = "".join([
        f'<span class="alert-badge">⚠️ {row["user"]} — {row["risk_score"]:.0f}</span>'
        for _, row in high_risk_users.head(10).iterrows()
    ])
    more_text = f'<span style="color:#aaa; font-size:12px;">+{len(high_risk_users)-10} more</span>' if len(high_risk_users) > 10 else ""

    st.markdown(f"""
        <div class="alert-banner">
            <h3>🚨 ACTIVE SECURITY ALERTS — {len(high_risk_users)} HIGH RISK USER{'S' if len(high_risk_users) > 1 else ''} DETECTED</h3>
            <div class="alert-row">
                {badges_html}
                {more_text}
            </div>
            <div class="alert-meta">
                ⏱ Alert generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
                🔍 Action required: Open <b>User Drilldown</b> tab to investigate &nbsp;|&nbsp;
                📄 Generate PDF report for each flagged user
            </div>
        </div>
    """, unsafe_allow_html=True)

if len(med_risk_users) > 0:
    med_badges = "".join([
        f'<span class="warning-badge">{row["user"]} — {row["risk_score"]:.0f}</span>'
        for _, row in med_risk_users.head(8).iterrows()
    ])
    more_med = f'+{len(med_risk_users)-8} more' if len(med_risk_users) > 8 else ""
    st.markdown(f"""
        <div class="warning-banner">
            <h4>⚠️ MONITORING WATCH — {len(med_risk_users)} Medium Risk User{'s' if len(med_risk_users) > 1 else ''}</h4>
            <div>{med_badges} <span style="color:#aaa;font-size:11px;">{more_med}</span></div>
        </div>
    """, unsafe_allow_html=True)

if len(high_risk_users) == 0 and len(med_risk_users) == 0:
    st.markdown("""
        <div class="all-clear">
            ✅ ALL CLEAR — No anomalous users detected in current dataset
        </div>
    """, unsafe_allow_html=True)

st.markdown("---")
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📊 Risk Overview",
    "👤 User Drilldown",
    "🔥 Feature Analysis",
    "📋 Full User Table",
    "ℹ️ About"
])

# ════════════════════════════════════════
# TAB 1 — RISK OVERVIEW
# ════════════════════════════════════════
with tab1:
    col_left, col_right = st.columns(2)

    # Chart 1: Top 20 users
    with col_left:
        st.subheader("Top 20 Highest-Risk Users")
        top20 = df.head(20).copy()
        bar_colors = top20["risk_level"].map(PALETTE)

        fig, ax = plt.subplots(figsize=(8, 6))
        bars = ax.barh(top20["user"], top20["risk_score"],
                       color=bar_colors, edgecolor="white")
        for bar, score in zip(bars, top20["risk_score"]):
            ax.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height()/2,
                    f"{score:.1f}", va="center", ha="left", fontsize=8)
        ax.set_xlabel("Risk Score")
        ax.set_title("Top 20 Highest-Risk Users — Isolation Forest")
        ax.set_xlim(0, 115)
        ax.invert_yaxis()
        legend_elements = [Patch(facecolor=PALETTE["High"],   label="High Risk"),
                           Patch(facecolor=PALETTE["Medium"], label="Medium Risk"),
                           Patch(facecolor=PALETTE["Low"],    label="Low Risk")]
        ax.legend(handles=legend_elements, loc="lower right")
        fig.tight_layout()
        st.pyplot(fig)
        plt.close()

    # Chart 2: Risk distribution histogram
    with col_right:
        st.subheader("Risk Score Distribution")
        fig, ax = plt.subplots(figsize=(8, 6))
        ax.hist(df[df["risk_level"] == "Low"]["risk_score"],
                bins=30, color=PALETTE["Low"], alpha=0.8, label="Low Risk", edgecolor="white")
        ax.hist(df[df["risk_level"] == "Medium"]["risk_score"],
                bins=20, color=PALETTE["Medium"], alpha=0.8, label="Medium Risk", edgecolor="white")
        ax.hist(df[df["risk_level"] == "High"]["risk_score"],
                bins=10, color=PALETTE["High"], alpha=0.8, label="High Risk", edgecolor="white")
        ax.axvline(70, color="red",    linestyle="--", linewidth=1.5, label="High threshold (70)")
        ax.axvline(40, color="orange", linestyle="--", linewidth=1.5, label="Medium threshold (40)")
        ax.set_xlabel("Risk Score (0 = Normal, 100 = Highly Anomalous)")
        ax.set_ylabel("Number of Users")
        ax.set_title("User Risk Score Distribution")
        ax.legend()
        fig.tight_layout()
        st.pyplot(fig)
        plt.close()

    # Chart 3: Email vs USB scatter
    st.subheader("External Email Rate vs USB Usage")
    fig, ax = plt.subplots(figsize=(10, 5))
    scatter = ax.scatter(
        df["external_email_rate"], df["usb_connections"],
        c=df["risk_score"], cmap="RdYlGn_r",
        alpha=0.7, s=60, edgecolors="white", linewidths=0.3, vmin=0, vmax=100
    )
    top10 = df.head(10)
    for _, row in top10.iterrows():
        ax.annotate(row["user"], (row["external_email_rate"], row["usb_connections"]),
                    fontsize=7, ha="left", va="bottom", color="darkred", fontweight="bold")
    cbar = plt.colorbar(scatter, ax=ax)
    cbar.set_label("Risk Score")
    ax.set_xlabel("External Email Rate (0=Only Internal, 1=All External)")
    ax.set_ylabel("USB Connection Count")
    ax.set_title("External Email Rate vs USB Usage (Colored by Risk Score)")
    fig.tight_layout()
    st.pyplot(fig)
    plt.close()

# ════════════════════════════════════════
# TAB 2 — USER DRILLDOWN
# ════════════════════════════════════════
with tab2:
    st.subheader("Individual User Drilldown")
    st.markdown("Select any user to see their full behavioral profile and risk breakdown.")

    # User selector
    high_risk_users = df[df["risk_level"] == "High"]["user"].tolist()
    all_users = df["user"].tolist()

    selected_user = st.selectbox(
        "Select a user to investigate:",
        options=all_users,
        index=0,
        help="High risk users appear at the top"
    )

    user_data = df[df["user"] == selected_user].iloc[0]
    risk_level = user_data["risk_level"]
    risk_score = user_data["risk_score"]

    # Risk badge
    color = PALETTE.get(str(risk_level), "#888")
    st.markdown(f"""
        <div style='background:{color}22; border-left: 5px solid {color};
                    padding: 15px; border-radius: 5px; margin-bottom: 20px;'>
            <h3 style='color:{color}; margin:0;'>
                {selected_user} — {risk_level} Risk
            </h3>
            <p style='margin:5px 0 0 0; font-size:18px;'>
                Risk Score: <strong style='color:{color}'>{risk_score:.1f} / 100</strong>
            </p>
        </div>
    """, unsafe_allow_html=True)

    # Feature breakdown
    feature_cols = {
        "Login Behavior": ["total_logins", "off_hours_login_rate", "weekend_login_rate", "unique_pcs_used"],
        "File Access": ["total_file_events", "sensitive_file_rate", "file_deletions", "off_hours_file_rate"],
        "Email Behavior": ["total_emails", "external_email_rate", "attachment_rate", "off_hours_email_rate"],
        "Device Usage": ["usb_connections", "off_hours_usb_rate"],
    }

    col_a, col_b = st.columns(2)
    cols = [col_a, col_b]

    for i, (category, features) in enumerate(feature_cols.items()):
        valid_features = [f for f in features if f in user_data.index]
        if not valid_features:
            continue
        with cols[i % 2]:
            st.markdown(f"**{category}**")
            for feat in valid_features:
                val = user_data[feat]
                # Compare to population average
                pop_avg = df[feat].mean()
                delta = val - pop_avg
                delta_str = f"+{delta:.2f}" if delta > 0 else f"{delta:.2f}"
                st.metric(
                    label=feat.replace("_", " ").title(),
                    value=f"{val:.2f}" if isinstance(val, float) else int(val),
                    delta=f"{delta_str} vs avg",
                    delta_color="inverse" if "rate" in feat or feat in ["file_deletions", "usb_connections"] else "normal"
                )

    # Radar-style bar chart for this user vs population
    st.markdown("---")
    st.subheader("Behavioral Profile vs Population Average")

    rate_features = [c for c in df.columns if "rate" in c and c != "risk_score"]
    if rate_features:
        user_vals = [user_data[f] for f in rate_features]
        avg_vals  = [df[f].mean() for f in rate_features]
        labels    = [f.replace("_", " ").replace(" rate", "").title() for f in rate_features]

        x = np.arange(len(labels))
        width = 0.35
        fig, ax = plt.subplots(figsize=(10, 4))
        ax.bar(x - width/2, user_vals, width, label=selected_user, color=color, alpha=0.85)
        ax.bar(x + width/2, avg_vals,  width, label="Population Avg", color="#888", alpha=0.6)
        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=30, ha="right", fontsize=9)
        ax.set_ylabel("Rate")
        ax.set_title(f"{selected_user} vs Population Average — Behavioral Features")
        ax.legend()
        fig.tight_layout()
        st.pyplot(fig)
        plt.close()

    # ── PDF EXPORT ──
    st.markdown("---")
    st.subheader("📄 Export Analyst Report")
    st.markdown("Generate a one-page PDF investigation report for this user.")

    if st.button(f"⬇️ Generate PDF Report for {selected_user}", type="primary"):
        with st.spinner("Generating PDF report..."):
            fig_bytes = None
            rate_features = [c for c in df.columns if "rate" in c and c != "risk_score"]
            if rate_features:
                user_vals = [user_data[f] for f in rate_features]
                avg_vals  = [df[f].mean() for f in rate_features]
                labels    = [f.replace("_", " ").replace(" rate", "").title() for f in rate_features]
                x = np.arange(len(labels))
                width = 0.35
                fig_pdf, ax_pdf = plt.subplots(figsize=(10, 3.5))
                ax_pdf.bar(x - width/2, user_vals, width, label=selected_user, color=color, alpha=0.85)
                ax_pdf.bar(x + width/2, avg_vals,  width, label="Population Avg", color="#888", alpha=0.6)
                ax_pdf.set_xticks(x)
                ax_pdf.set_xticklabels(labels, rotation=30, ha="right", fontsize=8)
                ax_pdf.set_ylabel("Rate")
                ax_pdf.set_title(f"{selected_user} vs Population Average")
                ax_pdf.legend()
                fig_pdf.tight_layout()
                buf = io.BytesIO()
                fig_pdf.savefig(buf, format="png", dpi=120)
                plt.close(fig_pdf)
                fig_bytes = buf.getvalue()

            pdf_bytes = generate_pdf_report(selected_user, user_data, df, fig_bytes)

        st.download_button(
            label=f"📥 Download {selected_user}_report.pdf",
            data=pdf_bytes,
            file_name=f"{selected_user}_threat_report_{datetime.now().strftime('%Y%m%d')}.pdf",
            mime="application/pdf",
        )
        st.success("✅ Report ready — click above to download!")

# ════════════════════════════════════════
# TAB 3 — FEATURE ANALYSIS
# ════════════════════════════════════════
with tab3:
    col_l, col_r = st.columns(2)

    # Heatmap
    with col_l:
        st.subheader("Feature Correlation Heatmap")
        heatmap_cols = [
            "risk_score", "total_logins", "off_hours_login_rate", "weekend_login_rate",
            "unique_pcs_used", "total_file_events", "sensitive_file_rate",
            "file_deletions", "total_emails", "external_email_rate",
            "attachment_rate", "usb_connections", "off_hours_usb_rate"
        ]
        heatmap_cols = [c for c in heatmap_cols if c in df.columns]
        corr = df[heatmap_cols].corr()
        fig, ax = plt.subplots(figsize=(8, 7))
        mask = np.triu(np.ones_like(corr, dtype=bool))
        sns.heatmap(corr, mask=mask, annot=True, fmt=".2f", cmap="RdYlGn_r",
                    vmin=-1, vmax=1, center=0, ax=ax,
                    annot_kws={"size": 7}, linewidths=0.5)
        ax.set_title("Feature Correlation Heatmap\n(Red = High Positive Correlation with Risk)", fontsize=11)
        fig.tight_layout()
        st.pyplot(fig)
        plt.close()

    # Off-hours boxplot
    with col_r:
        st.subheader("Off-Hours Activity: Normal vs Flagged")
        needed = ["is_anomaly", "off_hours_login_rate", "off_hours_file_rate", "off_hours_email_rate"]
        if all(c in df.columns for c in needed):
            plot_df = df[needed].copy()
            plot_df["user_type"] = plot_df["is_anomaly"].map(
                {True: "Flagged (Anomaly)", False: "Normal"}
            )
            melted = plot_df.melt(
                id_vars="user_type",
                value_vars=["off_hours_login_rate", "off_hours_file_rate", "off_hours_email_rate"],
                var_name="Feature", value_name="Rate"
            )
            melted["Feature"] = (melted["Feature"]
                                 .str.replace("_rate", "")
                                 .str.replace("_", " ")
                                 .str.title())
            fig, ax = plt.subplots(figsize=(8, 7))
            sns.boxplot(data=melted, x="Feature", y="Rate", hue="user_type",
                        palette={"Normal": "#3498db", "Flagged (Anomaly)": "#e74c3c"},
                        ax=ax, width=0.5)
            ax.set_ylabel("Rate (0 = Never, 1 = Always)")
            ax.set_xlabel("")
            ax.set_title("Off-Hours Activity Rate: Normal vs Flagged Users")
            ax.legend(title="User Type")
            fig.tight_layout()
            st.pyplot(fig)
            plt.close()

    # Top predictive features bar chart
    st.subheader("Most Predictive Features (Correlation with Risk Score)")
    if "risk_score" in df.columns:
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        numeric_cols = [c for c in numeric_cols if c != "risk_score"]
        correlations = df[numeric_cols].corrwith(df["risk_score"]).abs().sort_values(ascending=False).head(10)
        fig, ax = plt.subplots(figsize=(10, 4))
        bars = ax.barh(correlations.index[::-1],
                       correlations.values[::-1],
                       color=["#e74c3c" if v > 0.7 else "#f39c12" if v > 0.4 else "#2ecc71"
                              for v in correlations.values[::-1]])
        ax.set_xlabel("Absolute Correlation with Risk Score")
        ax.set_title("Top 10 Features by Predictive Power")
        ax.axvline(0.7, color="red",    linestyle="--", alpha=0.5, label="Strong (0.7)")
        ax.axvline(0.4, color="orange", linestyle="--", alpha=0.5, label="Moderate (0.4)")
        ax.legend()
        fig.tight_layout()
        st.pyplot(fig)
        plt.close()

# ════════════════════════════════════════
# TAB 4 — FULL USER TABLE
# ════════════════════════════════════════
with tab4:
    st.subheader("Full User Risk Table")

    # Color-coded display
    def highlight_risk(row):
        if row["risk_level"] == "High":
            return ["background-color: #e74c3c22"] * len(row)
        elif row["risk_level"] == "Medium":
            return ["background-color: #f39c1222"] * len(row)
        return [""] * len(row)

    display_cols = ["user", "risk_score", "risk_level"] + [
        c for c in ["total_logins", "off_hours_login_rate", "external_email_rate",
                    "usb_connections", "file_deletions", "sensitive_file_rate"]
        if c in df_filtered.columns
    ]

    st.dataframe(
        df_filtered[display_cols].style.apply(highlight_risk, axis=1).format({
            "risk_score": "{:.1f}",
            "off_hours_login_rate": "{:.2f}",
            "external_email_rate": "{:.2f}",
            "sensitive_file_rate": "{:.2f}",
        }),
        use_container_width=True,
        height=500
    )

    # Download button
    csv = df_filtered.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="⬇️ Download Filtered Results as CSV",
        data=csv,
        file_name="risk_scores_filtered.csv",
        mime="text/csv"
    )

# ════════════════════════════════════════
# TAB 5 — ABOUT
# ════════════════════════════════════════
with tab5:
    st.subheader("About This Dashboard")
    st.markdown("""
    ### Machine Learning-Based Insider Threat Detection System
    
    This dashboard visualizes the output of a five-stage behavioral analytics pipeline
    designed to detect insider threats using unsupervised machine learning.
    
    **Pipeline Stages:**
    1. **Data Collection** — Consolidates login, file access, email, and USB device logs
    2. **Preprocessing** — Cleans, normalizes, and encodes raw behavioral data
    3. **Feature Engineering** — Extracts 17 behavioral indicators per user
    4. **Anomaly Detection** — Applies Isolation Forest to identify statistical deviations
    5. **Risk Scoring** — Classifies users into Low / Medium / High risk tiers
    
    **Risk Thresholds:**
    | Level | Score Range | Action |
    |-------|-------------|--------|
    | 🟢 Low | 0 – 39 | Monitor passively |
    | 🟡 Medium | 40 – 69 | Review activity logs |
    | 🔴 High | 70 – 100 | Immediate analyst review |
    
    **Dataset:** CERT 4.2 Synthetic Insider Threat Dataset  
    **Algorithm:** Isolation Forest (scikit-learn)  
    **Built by:** University of the People — MSIT 5910 Capstone  
    
    ---
    **GitHub Repository:** https://github.com/Flipflop-ux/insider-threat-detection-system
    """)
