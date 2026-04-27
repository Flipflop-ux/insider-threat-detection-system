"""
Insider Threat Detection Dashboard
Built with Streamlit — powered by Isolation Forest behavioral analytics.
"""

import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
import seaborn as sns

# ── PAGE CONFIG ──────────────────────────────────────────────
st.set_page_config(
    page_title="Insider Threat Detection",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── STYLING ───────────────────────────────────────────────────
st.markdown("""
    <style>
    .block-container {
        padding-top: 2rem;
    }

    h1 {
        font-size: 2.4rem !important;
        font-weight: 700 !important;
    }

    h2, h3 {
        font-weight: 650 !important;
    }

    .stTabs [data-baseweb="tab-list"] {
        gap: 24px;
    }

    .stTabs [data-baseweb="tab"] {
        font-size: 16px;
        padding: 10px 0;
    }

    .stMetric {
        background-color: rgba(255, 255, 255, 0.03);
        padding: 18px;
        border-radius: 12px;
        border: 1px solid rgba(255, 255, 255, 0.08);
    }

    .high-risk { color: #e74c3c; font-weight: bold; }
    .medium-risk { color: #f39c12; font-weight: bold; }
    .low-risk { color: #2ecc71; font-weight: bold; }
    </style>
""", unsafe_allow_html=True)

PALETTE = {
    "Low": "#2ecc71",
    "Medium": "#f39c12",
    "High": "#e74c3c"
}

# ── SIDEBAR ───────────────────────────────────────────────────
st.sidebar.title("Insider Threat Detection")
st.sidebar.caption("Behavioral Risk Dashboard")
st.sidebar.markdown("---")

st.sidebar.markdown("### Data Input")

uploaded_file = st.sidebar.file_uploader(
    "Upload anomaly_scores.csv",
    type=["csv"],
    help="Upload a CSV containing user risk scores generated from the model."
)

st.sidebar.markdown("---")
st.sidebar.markdown("### Filter Options")


# ── RISK LEVEL FUNCTION ───────────────────────────────────────
def assign_risk_level(score):
    if score >= 70:
        return "High"
    elif score >= 40:
        return "Medium"
    else:
        return "Low"


# ── LOAD DATA ─────────────────────────────────────────────────
@st.cache_data
def load_data(file):
    df = pd.read_csv(file)

    if "risk_score" not in df.columns:
        st.error("The uploaded CSV must include a 'risk_score' column.")
        st.stop()

    if "user" not in df.columns:
        if "user_id" in df.columns:
            df = df.rename(columns={"user_id": "user"})
        else:
            df["user"] = [f"User_{i+1}" for i in range(len(df))]

    df["risk_level"] = df["risk_score"].apply(assign_risk_level)
    df = df.sort_values("risk_score", ascending=False).reset_index(drop=True)

    return df


@st.cache_data
def load_sample_data():
    np.random.seed(42)
    n = 500
    users = [f"U{str(i).zfill(4)}" for i in range(n)]

    low_users = pd.DataFrame({
        "user": users[:350],
        "risk_score": np.random.uniform(0, 39, 350),
        "total_logins": np.random.randint(50, 200, 350),
        "off_hours_login_rate": np.random.uniform(0, 0.1, 350),
        "weekend_login_rate": np.random.uniform(0, 0.1, 350),
        "unique_pcs_used": np.random.randint(1, 3, 350),
        "total_file_events": np.random.randint(100, 500, 350),
        "sensitive_file_rate": np.random.uniform(0, 0.2, 350),
        "file_deletions": np.random.randint(0, 10, 350),
        "total_emails": np.random.randint(50, 300, 350),
        "external_email_rate": np.random.uniform(0, 0.05, 350),
        "attachment_rate": np.random.uniform(0.1, 0.3, 350),
        "usb_connections": np.random.randint(0, 5, 350),
        "off_hours_usb_rate": np.random.uniform(0, 0.1, 350),
        "off_hours_file_rate": np.random.uniform(0, 0.15, 350),
        "off_hours_email_rate": np.random.uniform(0.1, 0.3, 350),
        "is_anomaly": False,
    })

    medium_users = pd.DataFrame({
        "user": users[350:475],
        "risk_score": np.random.uniform(40, 69, 125),
        "total_logins": np.random.randint(150, 350, 125),
        "off_hours_login_rate": np.random.uniform(0.15, 0.35, 125),
        "weekend_login_rate": np.random.uniform(0.1, 0.3, 125),
        "unique_pcs_used": np.random.randint(2, 5, 125),
        "total_file_events": np.random.randint(400, 900, 125),
        "sensitive_file_rate": np.random.uniform(0.2, 0.45, 125),
        "file_deletions": np.random.randint(8, 25, 125),
        "total_emails": np.random.randint(200, 500, 125),
        "external_email_rate": np.random.uniform(0.08, 0.25, 125),
        "attachment_rate": np.random.uniform(0.25, 0.5, 125),
        "usb_connections": np.random.randint(5, 15, 125),
        "off_hours_usb_rate": np.random.uniform(0.1, 0.3, 125),
        "off_hours_file_rate": np.random.uniform(0.15, 0.35, 125),
        "off_hours_email_rate": np.random.uniform(0.2, 0.4, 125),
        "is_anomaly": False,
    })

    high_users = pd.DataFrame({
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

    df = pd.concat([low_users, medium_users, high_users])
    df["risk_level"] = df["risk_score"].apply(assign_risk_level)
    df = df.sort_values("risk_score", ascending=False).reset_index(drop=True)

    return df


# ── LOAD SELECTED DATA ────────────────────────────────────────
if uploaded_file:
    df = load_data(uploaded_file)
    st.sidebar.success(f"Loaded {len(df)} users")
else:
    df = load_sample_data()
    st.sidebar.info("Using sample data. Upload anomaly_scores.csv to view your model results.")


# ── SIDEBAR FILTERS ───────────────────────────────────────────
risk_filter = st.sidebar.multiselect(
    "Risk Level",
    options=["High", "Medium", "Low"],
    default=["High", "Medium", "Low"]
)

score_range = st.sidebar.slider(
    "Risk Score Range",
    min_value=0,
    max_value=100,
    value=(0, 100)
)

df_filtered = df[
    (df["risk_level"].isin(risk_filter)) &
    (df["risk_score"] >= score_range[0]) &
    (df["risk_score"] <= score_range[1])
]

st.sidebar.markdown("---")
st.sidebar.markdown(f"**Showing:** {len(df_filtered)} of {len(df)} users")


# ── MAIN HEADER ───────────────────────────────────────────────
st.title("Insider Threat Detection Dashboard")
st.caption(
    "Behavioral anomaly detection using Isolation Forest. "
    "Risk scores highlight unusual user activity patterns for analyst review."
)

st.markdown("---")


# ── KPI METRICS ROW ───────────────────────────────────────────
col1, col2, col3, col4, col5 = st.columns(5)

total_users = len(df)
high_risk = len(df[df["risk_level"] == "High"])
medium_risk = len(df[df["risk_level"] == "Medium"])
low_risk = len(df[df["risk_level"] == "Low"])
avg_score = df["risk_score"].mean()

with col1:
    st.metric("Total Users", total_users)

with col2:
    st.metric("High Risk", high_risk, delta=f"{high_risk / total_users * 100:.1f}%")

with col3:
    st.metric("Medium Risk", medium_risk, delta=f"{medium_risk / total_users * 100:.1f}%")

with col4:
    st.metric("Low Risk", low_risk, delta=f"{low_risk / total_users * 100:.1f}%")

with col5:
    st.metric("Average Risk Score", f"{avg_score:.1f}")


st.markdown("---")


# ── TABS ──────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "Risk Overview",
    "User Drilldown",
    "Feature Analysis",
    "Full User Table",
    "About"
])


# ════════════════════════════════════════
# TAB 1 — RISK OVERVIEW
# ════════════════════════════════════════
with tab1:
    col_left, col_right = st.columns(2)

    with col_left:
        st.subheader("Top 20 Highest-Risk Users")

        top20 = df.head(20).copy()
        bar_colors = top20["risk_level"].map(PALETTE)

        fig, ax = plt.subplots(figsize=(8, 6))
        bars = ax.barh(
            top20["user"],
            top20["risk_score"],
            color=bar_colors,
            edgecolor="white"
        )

        for bar, score in zip(bars, top20["risk_score"]):
            ax.text(
                bar.get_width() + 0.5,
                bar.get_y() + bar.get_height() / 2,
                f"{score:.1f}",
                va="center",
                ha="left",
                fontsize=8
            )

        ax.set_xlabel("Risk Score")
        ax.set_title("Top 20 Highest-Risk Users")
        ax.set_xlim(0, 115)
        ax.invert_yaxis()

        legend_elements = [
            Patch(facecolor=PALETTE["High"], label="High Risk"),
            Patch(facecolor=PALETTE["Medium"], label="Medium Risk"),
            Patch(facecolor=PALETTE["Low"], label="Low Risk")
        ]

        ax.legend(handles=legend_elements, loc="lower right")
        fig.tight_layout()
        st.pyplot(fig)
        plt.close()

    with col_right:
        st.subheader("Risk Score Distribution")

        fig, ax = plt.subplots(figsize=(8, 6))

        ax.hist(
            df[df["risk_level"] == "Low"]["risk_score"],
            bins=30,
            color=PALETTE["Low"],
            alpha=0.8,
            label="Low Risk",
            edgecolor="white"
        )

        ax.hist(
            df[df["risk_level"] == "Medium"]["risk_score"],
            bins=20,
            color=PALETTE["Medium"],
            alpha=0.8,
            label="Medium Risk",
            edgecolor="white"
        )

        ax.hist(
            df[df["risk_level"] == "High"]["risk_score"],
            bins=10,
            color=PALETTE["High"],
            alpha=0.8,
            label="High Risk",
            edgecolor="white"
        )

        ax.axvline(70, color="red", linestyle="--", linewidth=1.5, label="High Threshold")
        ax.axvline(40, color="orange", linestyle="--", linewidth=1.5, label="Medium Threshold")

        ax.set_xlabel("Risk Score")
        ax.set_ylabel("Number of Users")
        ax.set_title("User Risk Score Distribution")
        ax.legend()

        fig.tight_layout()
        st.pyplot(fig)
        plt.close()

    st.subheader("External Email Rate vs USB Usage")

    if "external_email_rate" in df.columns and "usb_connections" in df.columns:
        fig, ax = plt.subplots(figsize=(10, 5))

        scatter = ax.scatter(
            df["external_email_rate"],
            df["usb_connections"],
            c=df["risk_score"],
            cmap="RdYlGn_r",
            alpha=0.7,
            s=60,
            edgecolors="white",
            linewidths=0.3,
            vmin=0,
            vmax=100
        )

        top10 = df.head(10)

        for _, row in top10.iterrows():
            ax.annotate(
                row["user"],
                (row["external_email_rate"], row["usb_connections"]),
                fontsize=7,
                ha="left",
                va="bottom",
                color="darkred",
                fontweight="bold"
            )

        cbar = plt.colorbar(scatter, ax=ax)
        cbar.set_label("Risk Score")

        ax.set_xlabel("External Email Rate")
        ax.set_ylabel("USB Connection Count")
        ax.set_title("External Email Rate vs USB Usage")

        fig.tight_layout()
        st.pyplot(fig)
        plt.close()
    else:
        st.info("External email and USB usage columns are not available in this dataset.")


# ════════════════════════════════════════
# TAB 2 — USER DRILLDOWN
# ════════════════════════════════════════
with tab2:
    st.subheader("Individual User Drilldown")
    st.caption("Select a user to review their behavioral profile and risk score.")

    selected_user = st.selectbox(
        "Select a user to investigate:",
        options=df["user"].tolist(),
        index=0,
        help="Users are sorted by risk score from highest to lowest."
    )

    user_data = df[df["user"] == selected_user].iloc[0]
    risk_level = user_data["risk_level"]
    risk_score = user_data["risk_score"]
    color = PALETTE.get(str(risk_level), "#888")

    st.markdown(f"""
        <div style='background:{color}22; border-left: 5px solid {color};
                    padding: 15px; border-radius: 8px; margin-bottom: 20px;'>
            <h3 style='color:{color}; margin:0;'>
                {selected_user} — {risk_level} Risk
            </h3>
            <p style='margin:5px 0 0 0; font-size:18px;'>
                Risk Score: <strong style='color:{color}'>{risk_score:.1f} / 100</strong>
            </p>
        </div>
    """, unsafe_allow_html=True)

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
                pop_avg = df[feat].mean()
                delta = val - pop_avg
                delta_str = f"+{delta:.2f}" if delta > 0 else f"{delta:.2f}"

                st.metric(
                    label=feat.replace("_", " ").title(),
                    value=f"{val:.2f}" if isinstance(val, float) else int(val),
                    delta=f"{delta_str} vs avg",
                    delta_color="inverse" if "rate" in feat or feat in ["file_deletions", "usb_connections"] else "normal"
                )

    st.markdown("---")
    st.subheader("Behavioral Profile vs Population Average")

    rate_features = [c for c in df.columns if "rate" in c and c != "risk_score"]

    if rate_features:
        user_vals = [user_data[f] for f in rate_features]
        avg_vals = [df[f].mean() for f in rate_features]
        labels = [f.replace("_", " ").replace(" rate", "").title() for f in rate_features]

        x = np.arange(len(labels))
        width = 0.35

        fig, ax = plt.subplots(figsize=(10, 4))

        ax.bar(x - width / 2, user_vals, width, label=selected_user, color=color, alpha=0.85)
        ax.bar(x + width / 2, avg_vals, width, label="Population Average", color="#888", alpha=0.6)

        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=30, ha="right", fontsize=9)
        ax.set_ylabel("Rate")
        ax.set_title(f"{selected_user} vs Population Average")
        ax.legend()

        fig.tight_layout()
        st.pyplot(fig)
        plt.close()
    else:
        st.info("No rate-based behavioral features are available for this dataset.")


# ════════════════════════════════════════
# TAB 3 — FEATURE ANALYSIS
# ════════════════════════════════════════
with tab3:
    col_l, col_r = st.columns(2)

    with col_l:
        st.subheader("Feature Correlation Heatmap")

        heatmap_cols = [
            "risk_score",
            "total_logins",
            "off_hours_login_rate",
            "weekend_login_rate",
            "unique_pcs_used",
            "total_file_events",
            "sensitive_file_rate",
            "file_deletions",
            "total_emails",
            "external_email_rate",
            "attachment_rate",
            "usb_connections",
            "off_hours_usb_rate"
        ]

        heatmap_cols = [c for c in heatmap_cols if c in df.columns]

        if len(heatmap_cols) > 1:
            corr = df[heatmap_cols].corr()
            fig, ax = plt.subplots(figsize=(8, 7))
            mask = np.triu(np.ones_like(corr, dtype=bool))

            sns.heatmap(
                corr,
                mask=mask,
                annot=True,
                fmt=".2f",
                cmap="RdYlGn_r",
                vmin=-1,
                vmax=1,
                center=0,
                ax=ax,
                annot_kws={"size": 7},
                linewidths=0.5
            )

            ax.set_title("Feature Correlation Heatmap", fontsize=11)
            fig.tight_layout()
            st.pyplot(fig)
            plt.close()
        else:
            st.info("Not enough numeric feature columns are available for a heatmap.")

    with col_r:
        st.subheader("Off-Hours Activity")

        needed = [
            "is_anomaly",
            "off_hours_login_rate",
            "off_hours_file_rate",
            "off_hours_email_rate"
        ]

        if all(c in df.columns for c in needed):
            plot_df = df[needed].copy()
            plot_df["user_type"] = plot_df["is_anomaly"].map({
                True: "Flagged",
                False: "Normal"
            })

            melted = plot_df.melt(
                id_vars="user_type",
                value_vars=[
                    "off_hours_login_rate",
                    "off_hours_file_rate",
                    "off_hours_email_rate"
                ],
                var_name="Feature",
                value_name="Rate"
            )

            melted["Feature"] = (
                melted["Feature"]
                .str.replace("_rate", "")
                .str.replace("_", " ")
                .str.title()
            )

            fig, ax = plt.subplots(figsize=(8, 7))

            sns.boxplot(
                data=melted,
                x="Feature",
                y="Rate",
                hue="user_type",
                palette={
                    "Normal": "#3498db",
                    "Flagged": "#e74c3c"
                },
                ax=ax,
                width=0.5
            )

            ax.set_ylabel("Rate")
            ax.set_xlabel("")
            ax.set_title("Off-Hours Activity Rate")
            ax.legend(title="User Type")

            fig.tight_layout()
            st.pyplot(fig)
            plt.close()
        else:
            st.info("Off-hours activity columns are not available in this dataset.")

    st.subheader("Most Predictive Features")

    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    numeric_cols = [c for c in numeric_cols if c != "risk_score"]

    if "risk_score" in df.columns and numeric_cols:
        correlations = (
            df[numeric_cols]
            .corrwith(df["risk_score"])
            .abs()
            .sort_values(ascending=False)
            .head(10)
        )

        fig, ax = plt.subplots(figsize=(10, 4))

        bars = ax.barh(
            correlations.index[::-1],
            correlations.values[::-1],
            color=[
                "#e74c3c" if v > 0.7 else "#f39c12" if v > 0.4 else "#2ecc71"
                for v in correlations.values[::-1]
            ]
        )

        ax.set_xlabel("Absolute Correlation with Risk Score")
        ax.set_title("Top 10 Features by Predictive Power")
        ax.axvline(0.7, color="red", linestyle="--", alpha=0.5, label="Strong")
        ax.axvline(0.4, color="orange", linestyle="--", alpha=0.5, label="Moderate")
        ax.legend()

        fig.tight_layout()
        st.pyplot(fig)
        plt.close()
    else:
        st.info("Not enough numeric columns are available for feature analysis.")


# ════════════════════════════════════════
# TAB 4 — FULL USER TABLE
# ════════════════════════════════════════
with tab4:
    st.subheader("Full User Risk Table")

    def highlight_risk(row):
        if row["risk_level"] == "High":
            return ["background-color: #e74c3c22"] * len(row)
        elif row["risk_level"] == "Medium":
            return ["background-color: #f39c1222"] * len(row)
        elif row["risk_level"] == "Low":
            return ["background-color: #2ecc7122"] * len(row)
        return [""] * len(row)

    display_cols = ["user", "risk_score", "risk_level"] + [
        c for c in [
            "total_logins",
            "off_hours_login_rate",
            "external_email_rate",
            "usb_connections",
            "file_deletions",
            "sensitive_file_rate"
        ]
        if c in df_filtered.columns
    ]

    format_dict = {
        "risk_score": "{:.1f}",
        "off_hours_login_rate": "{:.2f}",
        "external_email_rate": "{:.2f}",
        "sensitive_file_rate": "{:.2f}",
    }

    format_dict = {
        k: v for k, v in format_dict.items()
        if k in df_filtered.columns
    }

    st.dataframe(
        df_filtered[display_cols]
        .style
        .apply(highlight_risk, axis=1)
        .format(format_dict),
        use_container_width=True,
        height=500
    )

    csv = df_filtered.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="Download Filtered Results as CSV",
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
    This dashboard visualizes the output of a behavioral analytics pipeline designed to detect unusual user activity patterns using unsupervised machine learning.

    **Pipeline Stages**

    1. Data Collection — Consolidates login, file access, email, and USB device logs  
    2. Preprocessing — Cleans, normalizes, and prepares raw behavioral data  
    3. Feature Engineering — Extracts behavioral indicators for each user  
    4. Anomaly Detection — Applies Isolation Forest to identify unusual patterns  
    5. Risk Scoring — Classifies users into Low, Medium, and High risk tiers  

    **Risk Thresholds**

    | Level | Score Range | Recommended Action |
    |-------|-------------|--------------------|
    | Low | 0–39 | Monitor passively |
    | Medium | 40–69 | Review activity logs |
    | High | 70–100 | Prioritize analyst review |

    **Dataset:** CERT 4.2 Synthetic Insider Threat Dataset  
    **Algorithm:** Isolation Forest  
    **Project:** MSIT Capstone Project  
    """)
