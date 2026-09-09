"""
Code Sentinel AI - BYOK Multi-LLM Code Review & Security Auditor
Intelligent SAST + Generative AI Code Review Assistant (Problem Code: JP-003)
"""
import os
import json
import tempfile
from datetime import datetime
import streamlit as st
import pandas as pd

# Local core modules
from core.repo_cloner import (
    clone_github_repo,
    scan_target_files,
    cleanup_cloned_repo,
    get_offline_demo_path,
    detect_code_language,
)
from core.static_scanner import analyze_repository, get_codebase_verbal_rating
from core.ai_patcher import generate_ai_remediation, _get_offline_heuristic_fix, enrich_code_audit

# Page Configuration
st.set_page_config(
    page_title="Code Sentinel AI | Intelligent Code Auditor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom High-End Styling (Theme-Adaptive & Beautiful Color Palette)
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

    /* Global Typography & Background Glow */
    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    code, pre, .stCodeBlock {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Ambient Background Mesh */
    .stApp {
        background-color: #080c16;
        background-image: 
            radial-gradient(ellipse 80% 50% at 50% -15%, rgba(99, 102, 241, 0.18), transparent 60%),
            radial-gradient(circle 600px at 95% 25%, rgba(14, 165, 233, 0.08), transparent 60%),
            radial-gradient(circle 500px at 5% 75%, rgba(168, 85, 247, 0.06), transparent 50%);
        background-attachment: fixed;
    }

    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background: rgba(11, 17, 32, 0.88) !important;
        backdrop-filter: blur(20px);
        border-right: 1px solid rgba(255, 255, 255, 0.08);
    }

    /* Primary & Secondary Buttons */
    div.stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 45%, #06b6d4 100%) !important;
        color: #ffffff !important;
        font-weight: 700 !important;
        letter-spacing: 0.02em !important;
        border: none !important;
        border-radius: 12px !important;
        padding: 12px 24px !important;
        box-shadow: 0 4px 18px rgba(99, 102, 241, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.25) !important;
        transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1) !important;
    }
    div.stButton > button[kind="primary"]:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 8px 25px rgba(99, 102, 241, 0.55), inset 0 1px 0 rgba(255, 255, 255, 0.4) !important;
    }
    div.stButton > button[kind="secondary"] {
        background: rgba(30, 41, 59, 0.6) !important;
        color: #f1f5f9 !important;
        border: 1px solid rgba(255, 255, 255, 0.12) !important;
        border-radius: 10px !important;
        transition: all 0.2s ease !important;
        backdrop-filter: blur(8px) !important;
    }
    div.stButton > button[kind="secondary"]:hover {
        border-color: rgba(99, 102, 241, 0.6) !important;
        background: rgba(30, 41, 59, 0.9) !important;
        transform: translateY(-1px) !important;
    }

    /* Input Fields */
    div[data-baseweb="input"] {
        border-radius: 10px !important;
        background-color: rgba(15, 23, 42, 0.75) !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        transition: border-color 0.2s ease !important;
    }
    div[data-baseweb="input"]:focus-within {
        border-color: #6366f1 !important;
        box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.25) !important;
    }

    /* Radio Pills (Scope and Tabs) */
    div[data-testid="stRadio"] > div {
        background: rgba(15, 23, 42, 0.6);
        padding: 4px;
        border-radius: 12px;
        border: 1px solid rgba(255, 255, 255, 0.08);
    }

    /* Global Card Base */
    .stCard {
        border-radius: 16px;
        padding: 24px;
        border: 1px solid rgba(255, 255, 255, 0.08);
        background: linear-gradient(145deg, rgba(30, 41, 59, 0.5) 0%, rgba(15, 23, 42, 0.75) 100%);
        backdrop-filter: blur(16px);
        box-shadow: 0 10px 30px -5px rgba(0, 0, 0, 0.35);
        margin-bottom: 20px;
    }

    /* Hero Scorecard */
    .hero-scorecard {
        border-radius: 20px;
        padding: 32px 36px;
        margin-bottom: 24px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 24px;
        backdrop-filter: blur(20px);
        box-shadow: 0 16px 40px -10px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.1);
        position: relative;
        overflow: hidden;
    }

    /* Score Radial Badge */
    .score-badge {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        min-width: 155px;
        padding: 20px 28px;
        border-radius: 20px;
        background: rgba(11, 17, 32, 0.75);
        border: 2px solid;
        box-shadow: 0 12px 30px rgba(0, 0, 0, 0.45), inset 0 0 20px rgba(255, 255, 255, 0.03);
    }

    /* Stat KPI Cards (Balanced 5 Columns) */
    .stat-kpi-card {
        border-radius: 14px;
        padding: 16px 18px;
        text-align: left;
        background: linear-gradient(145deg, rgba(26, 36, 56, 0.7) 0%, rgba(13, 20, 36, 0.85) 100%);
        border: 1px solid rgba(255, 255, 255, 0.08);
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.25);
        transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        position: relative;
        overflow: hidden;
        height: 100%;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
    }
    .stat-kpi-card:hover {
        transform: translateY(-3px);
        box-shadow: 0 12px 32px rgba(0, 0, 0, 0.4);
        border-color: rgba(255, 255, 255, 0.16);
    }
    .kpi-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        font-size: 0.74rem;
        font-weight: 800;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        margin-bottom: 8px;
    }
    .kpi-val {
        font-size: 1.85rem;
        font-weight: 900;
        line-height: 1;
        letter-spacing: -0.02em;
        margin-bottom: 8px;
    }
    .kpi-bar {
        height: 3px;
        width: 100%;
        border-radius: 3px;
        margin-top: 4px;
    }

    /* Explainer Box */
    .explainer-box {
        border-radius: 12px;
        padding: 18px 22px;
        margin: 14px 0;
        background: linear-gradient(135deg, rgba(245, 158, 11, 0.07) 0%, rgba(15, 23, 42, 0.65) 100%);
        border: 1px solid rgba(245, 158, 11, 0.32);
        border-left: 5px solid #f59e0b;
        font-size: 0.95rem;
        line-height: 1.65;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.15);
    }

    /* Refactor & Debug Callout */
    .refactor-banner {
        border-radius: 12px;
        padding: 14px 20px;
        margin: 12px 0 16px 0;
        background: linear-gradient(135deg, rgba(16, 185, 129, 0.09) 0%, rgba(15, 23, 42, 0.65) 100%);
        border: 1px solid rgba(16, 185, 129, 0.35);
        border-left: 5px solid #10b981;
        font-size: 0.93rem;
        line-height: 1.6;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.15);
    }

    /* Severity Badges */
    .chip {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        font-weight: 800;
        font-size: 0.76rem;
        padding: 4px 12px;
        border-radius: 20px;
        letter-spacing: 0.04em;
        text-transform: uppercase;
    }
    .chip-crit { background: rgba(239, 68, 68, 0.16); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.35); }
    .chip-high { background: rgba(249, 115, 22, 0.16); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.35); }
    .chip-med  { background: rgba(234, 179, 8, 0.16);  color: #facc15; border: 1px solid rgba(234, 179, 8, 0.35); }
    .chip-low  { background: rgba(59, 130, 246, 0.16);  color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.35); }

    /* Issue Card */
    .issue-card {
        border-radius: 16px;
        padding: 24px;
        margin-bottom: 24px;
        border: 1px solid rgba(255, 255, 255, 0.08);
        background: linear-gradient(145deg, rgba(22, 30, 49, 0.8) 0%, rgba(13, 19, 33, 0.92) 100%);
        backdrop-filter: blur(14px);
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
    }

    /* Symmetric Code Panel Headers */
    .code-panel-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 10px 16px;
        border-top-left-radius: 10px;
        border-top-right-radius: 10px;
        font-size: 0.8rem;
        font-weight: 800;
        letter-spacing: 0.06em;
        margin-bottom: -6px;
    }
    .orig-header {
        background: linear-gradient(90deg, rgba(244, 63, 94, 0.18) 0%, rgba(244, 63, 94, 0.06) 100%);
        border: 1px solid rgba(244, 63, 94, 0.35);
        border-bottom: none;
        color: #fb7185;
    }
    .refac-header {
        background: linear-gradient(90deg, rgba(16, 185, 129, 0.18) 0%, rgba(16, 185, 129, 0.06) 100%);
        border: 1px solid rgba(16, 185, 129, 0.35);
        border-bottom: none;
        color: #34d399;
    }
    .code-panel-title {
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .indicator-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        display: inline-block;
    }
    .dot-orig {
        background-color: #f43f5e;
        box-shadow: 0 0 10px #f43f5e;
    }
    .dot-refac {
        background-color: #10b981;
        box-shadow: 0 0 10px #10b981;
    }

    /* Change Summary Card (Where & What) */
    .change-summary-card {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 16px;
        margin: 12px 0 18px 0;
        padding: 16px 20px;
        border-radius: 12px;
        background: rgba(13, 20, 36, 0.75);
        border: 1px solid rgba(99, 102, 241, 0.25);
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.2);
    }
    @media (max-width: 768px) {
        .change-summary-card {
            grid-template-columns: 1fr;
        }
    }
    .change-item {
        display: flex;
        flex-direction: column;
        gap: 6px;
    }
    .change-tag {
        font-size: 0.74rem;
        font-weight: 800;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        display: flex;
        align-items: center;
        gap: 6px;
    }
    .tag-where {
        color: #38bdf8;
    }
    .tag-what {
        color: #a78bfa;
    }
    .change-detail {
        font-size: 0.92rem;
        line-height: 1.55;
        color: #e2e8f0;
    }

    /* Terminal Inspector Card */
    .inspector-card {
        border-radius: 16px;
        padding: 20px 24px;
        margin: 16px 0 24px 0;
        background: linear-gradient(145deg, rgba(20, 28, 47, 0.85) 0%, rgba(11, 16, 28, 0.95) 100%);
        border: 1px solid rgba(99, 102, 241, 0.35);
        box-shadow: 0 12px 36px rgba(0, 0, 0, 0.35);
    }
    .mac-dots {
        display: inline-flex;
        gap: 6px;
        align-items: center;
        margin-right: 12px;
    }
    .mac-dot {
        width: 10px;
        height: 10px;
        border-radius: 50%;
        display: inline-block;
    }
    .mac-red { background: #ef4444; }
    .mac-yellow { background: #f59e0b; }
    .mac-green { background: #10b981; }

    .inspector-target-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 700;
        background: rgba(234, 179, 8, 0.2);
        color: #fde047;
        border: 1px solid rgba(234, 179, 8, 0.45);
        box-shadow: 0 0 12px rgba(234, 179, 8, 0.2);
    }

    .diff-badge-del {
        background: rgba(239, 68, 68, 0.22);
        color: #fca5a5;
        border: 1px solid rgba(239, 68, 68, 0.45);
        padding: 2px 8px;
        border-radius: 6px;
        font-size: 0.72rem;
        font-weight: 700;
    }
    .diff-badge-add {
        background: rgba(16, 185, 129, 0.22);
        color: #86efac;
        border: 1px solid rgba(16, 185, 129, 0.45);
        padding: 2px 8px;
        border-radius: 6px;
        font-size: 0.72rem;
        font-weight: 700;
    }

    /* Download Button Styling */
    div.stDownloadButton > button {
        background: linear-gradient(135deg, rgba(16, 185, 129, 0.22) 0%, rgba(6, 182, 212, 0.18) 100%) !important;
        border: 1px solid rgba(16, 185, 129, 0.5) !important;
        color: #34d399 !important;
        font-weight: 700 !important;
        border-radius: 12px !important;
        padding: 12px 24px !important;
        transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1) !important;
        box-shadow: 0 4px 18px rgba(16, 185, 129, 0.2) !important;
    }
    div.stDownloadButton > button:hover {
        background: linear-gradient(135deg, rgba(16, 185, 129, 0.38) 0%, rgba(6, 182, 212, 0.3) 100%) !important;
        border-color: #34d399 !important;
        color: #ffffff !important;
        transform: translateY(-2px) !important;
        box-shadow: 0 8px 25px rgba(16, 185, 129, 0.4) !important;
    }

    @keyframes pulse-dot {
        0%, 100% { opacity: 1; transform: scale(1); }
        50% { opacity: 0.5; transform: scale(0.85); }
    }
    .pulse-dot {
        display: inline-block;
        width: 6px;
        height: 6px;
        border-radius: 50%;
        background-color: currentColor;
        animation: pulse-dot 2s ease-in-out infinite;
    }

    /* Front Page Hero Components */
    .hero-container {
        text-align: center;
        padding: 40px 20px 24px 20px;
        position: relative;
    }
    .hero-badge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 6px 18px;
        border-radius: 30px;
        background: rgba(99, 102, 241, 0.12);
        border: 1px solid rgba(99, 102, 241, 0.3);
        margin-bottom: 20px;
        box-shadow: 0 0 20px rgba(99, 102, 241, 0.15);
    }
    .hero-title {
        font-size: 3.4rem;
        font-weight: 900;
        letter-spacing: -0.03em;
        margin: 0 0 16px 0;
        background: linear-gradient(135deg, #ffffff 20%, #c7d2fe 60%, #818cf8 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-shadow: 0 20px 50px rgba(0, 0, 0, 0.5);
    }
    .hero-sub {
        font-size: 1.15rem;
        color: #94a3b8;
        max-width: 720px;
        margin: 0 auto 28px auto;
        line-height: 1.7;
    }
    .capability-chips {
        display: flex;
        justify-content: center;
        gap: 12px;
        flex-wrap: wrap;
        margin-bottom: 32px;
    }
    .cap-chip {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        font-size: 0.78rem;
        font-weight: 700;
        padding: 6px 14px;
        border-radius: 20px;
        background: rgba(15, 23, 42, 0.7);
        border: 1px solid rgba(255, 255, 255, 0.08);
        color: #cbd5e1;
    }
    .quick-launch-card {
        border-radius: 20px;
        padding: 28px 32px;
        margin-bottom: 32px;
        background: linear-gradient(145deg, rgba(22, 33, 56, 0.85) 0%, rgba(13, 20, 36, 0.95) 100%);
        border: 1px solid rgba(99, 102, 241, 0.35);
        box-shadow: 0 20px 50px -10px rgba(0, 0, 0, 0.55), 0 0 30px rgba(99, 102, 241, 0.15);
        position: relative;
        overflow: hidden;
    }
    .feature-grid-card {
        border-radius: 16px;
        padding: 24px;
        background: linear-gradient(145deg, rgba(20, 28, 48, 0.7) 0%, rgba(11, 16, 30, 0.85) 100%);
        border: 1px solid rgba(255, 255, 255, 0.08);
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
        transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        height: 100%;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
    }
    .feature-grid-card:hover {
        transform: translateY(-4px);
        box-shadow: 0 16px 36px rgba(0, 0, 0, 0.45);
        border-color: rgba(99, 102, 241, 0.4);
    }

    /* Code Paste Expandable Tab & Text Area */
    div[data-testid="stExpander"] {
        border-radius: 16px !important;
        border: 1px solid rgba(99, 102, 241, 0.35) !important;
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.85) 0%, rgba(20, 26, 48, 0.75) 100%) !important;
        backdrop-filter: blur(16px) !important;
        box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.5), 0 0 20px rgba(99, 102, 241, 0.12) !important;
        margin-bottom: 24px !important;
        overflow: hidden !important;
        transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1) !important;
    }
    div[data-testid="stExpander"]:hover {
        border-color: rgba(99, 102, 241, 0.6) !important;
        box-shadow: 0 12px 35px -10px rgba(0, 0, 0, 0.6), 0 0 25px rgba(99, 102, 241, 0.22) !important;
    }
    div[data-testid="stExpander"] summary {
        padding: 14px 20px !important;
        font-size: 1.05rem !important;
        font-weight: 700 !important;
        color: #f1f5f9 !important;
        cursor: pointer !important;
        background: rgba(99, 102, 241, 0.08) !important;
        border-bottom: 1px solid rgba(99, 102, 241, 0.2) !important;
        transition: background 0.2s ease !important;
    }
    div[data-testid="stExpander"] summary:hover {
        background: rgba(99, 102, 241, 0.16) !important;
        color: #ffffff !important;
    }
    div[data-testid="stExpander"] summary svg {
        color: #818cf8 !important;
    }
    div[data-testid="stTextArea"] textarea {
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.88rem !important;
        line-height: 1.55 !important;
        background-color: #080d1a !important;
        border: 1px solid rgba(99, 102, 241, 0.25) !important;
        border-radius: 10px !important;
        color: #f1f5f9 !important;
    }
    div[data-testid="stTextArea"] textarea:focus {
        border-color: #6366f1 !important;
        box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.25) !important;
    }
</style>
""", unsafe_allow_html=True)

# Persistent BYOK Settings Helper
SETTINGS_FILE = os.path.join(os.path.dirname(__file__), ".byok_settings.json")

def load_saved_byok_settings() -> dict:
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_byok_settings(
    provider: str,
    model: str,
    api_key: str,
    custom_endpoint: str = "",
    github_url: str = "",
    github_token: str = ""
) -> bool:
    try:
        existing = load_saved_byok_settings()
        existing.update({
            "provider": provider,
            "model": model,
            "api_key": api_key,
            "custom_endpoint": custom_endpoint,
            "remembered": True,
            "updated_at": datetime.now().isoformat()
        })
        if github_url:
            existing["github_url"] = github_url
        if github_token:
            existing["github_token"] = github_token
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)
        return True
    except Exception:
        return False

def save_github_url(github_url: str, github_token: str = "") -> bool:
    try:
        existing = load_saved_byok_settings()
        existing["github_url"] = github_url
        if github_token:
            existing["github_token"] = github_token
        existing["updated_at"] = datetime.now().isoformat()
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)
        return True
    except Exception:
        return False

def clear_saved_byok_settings() -> bool:
    if os.path.exists(SETTINGS_FILE):
        try:
            os.remove(SETTINGS_FILE)
            return True
        except Exception:
            return False
    return True

# Session state initialization
if "analysis_results" not in st.session_state:
    st.session_state.analysis_results = None
if "target_path" not in st.session_state:
    st.session_state.target_path = None
if "active_remediations" not in st.session_state:
    st.session_state.active_remediations = {}
if "target_files" not in st.session_state:
    st.session_state.target_files = []
if "repo_display_name" not in st.session_state:
    st.session_state.repo_display_name = ""
if "selected_finding_id" not in st.session_state:
    st.session_state.selected_finding_id = None
if "selected_file_to_inspect" not in st.session_state:
    st.session_state.selected_file_to_inspect = None
if "audit_scope" not in st.session_state:
    st.session_state.audit_scope = "repo"
if "selected_file_for_audit" not in st.session_state:
    st.session_state.selected_file_for_audit = None
if "pasted_code_content" not in st.session_state:
    st.session_state.pasted_code_content = ""
if "pasted_code_filename" not in st.session_state:
    st.session_state.pasted_code_filename = "snippet.py"

# ================= SIDEBAR: 2-STEP ONBOARDING =================
with st.sidebar:
    st.markdown("""
    <div style="padding: 6px 0 14px 0;">
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 6px;">
            <div style="font-size: 2rem; line-height: 1; filter: drop-shadow(0 0 10px rgba(99, 102, 241, 0.4));">🛡️</div>
            <div>
                <div style="font-size: 1.28rem; font-weight: 900; color: #f8fafc; letter-spacing: -0.02em; line-height: 1.15;">Code Sentinel</div>
                <div style="font-size: 0.72rem; font-weight: 800; color: #38bdf8; letter-spacing: 0.08em; text-transform: uppercase;">AST & AI Defense Hub</div>
            </div>
        </div>
        <div style="font-size: 0.8rem; color: #94a3b8; line-height: 1.45;">
            Autonomous SAST Code Scanner & Multi-LLM Remediation
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.divider()

    # Load persistent settings
    saved_settings = load_saved_byok_settings()
    saved_github_url = saved_settings.get("github_url", "")
    saved_github_token = saved_settings.get("github_token", "")

    # STEP 1: GITHUB REPO CONNECTION
    st.markdown("#### 1️⃣ Connect GitHub Repo")
    use_demo = st.checkbox("⚡ Use Demo Repository (Instant Test)", value=False)

    github_url = ""
    github_token = ""
    step1_ready = False

    if not use_demo:
        github_url = st.text_input(
            "GitHub Repo URL",
            value=saved_github_url,
            placeholder="https://github.com/owner/repository",
            help="Public or private repository URL. Automatically remembered."
        )
        with st.expander("🔒 Private Repo Access Token (Optional)"):
            github_token = st.text_input(
                "Personal Access Token (PAT)",
                value=saved_github_token,
                type="password",
                help="Requires read access to repo contents."
            )
        step1_ready = bool(github_url.strip())
        if step1_ready and saved_github_url and saved_github_url == github_url.strip():
            st.caption("✨ *Auto-loaded previous repository entry.*")
    else:
        st.info("📦 Pre-loaded vulnerable sample repository active.")
        step1_ready = True
        st.success("✓ Demo Repo Ready", icon="✅")

    # AUDIT SCOPE: Whole Repo vs Specific File
    st.markdown("#### 🎯 Audit Scope")
    scope_options = ["🌐 Entire Repository", "📄 Specific File"]
    scope_default_idx = 1 if st.session_state.audit_scope == "file" else 0
    scope_pick = st.radio(
        "Scope Mode",
        scope_options,
        index=scope_default_idx,
        horizontal=True,
        label_visibility="collapsed",
        help="Select whether to audit all files across the repository or analyze one specific file."
    )
    st.session_state.audit_scope = "file" if "Specific File" in scope_pick else "repo"

    if st.session_state.audit_scope == "file":
        # Pre-populate demo files if demo mode is on
        if use_demo:
            if not st.session_state.target_files or st.session_state.repo_display_name != "demo_repos/vulnerable_sample":
                demo_root = get_offline_demo_path()
                st.session_state.target_path = demo_root
                st.session_state.repo_display_name = "demo_repos/vulnerable_sample"
                st.session_state.target_files = scan_target_files(demo_root)

        # If repo files not yet loaded, offer one-click indexing
        if not st.session_state.target_files and step1_ready:
            if st.button("📂 Fetch & List Repo Files", use_container_width=True, help="Index files in the repository to pick from"):
                with st.spinner("Fetching repository files..."):
                    try:
                        if not use_demo:
                            clone_res = clone_github_repo(github_url, github_token=github_token)
                            st.session_state.target_path = clone_res["path"]
                            st.session_state.repo_display_name = github_url
                        else:
                            st.session_state.target_path = get_offline_demo_path()
                            st.session_state.repo_display_name = "demo_repos/vulnerable_sample"
                        st.session_state.target_files = scan_target_files(st.session_state.target_path)
                        st.rerun()
                    except Exception as ex:
                        st.error(f"Could not load files: {ex}")

        if st.session_state.target_files:
            file_options = [f["rel_path"] for f in st.session_state.target_files]
            label_map = {f["rel_path"]: f.get("display_label", f["rel_path"]) for f in st.session_state.target_files}
            
            cur_idx = 0
            if st.session_state.selected_file_for_audit in file_options:
                cur_idx = file_options.index(st.session_state.selected_file_for_audit)

            chosen_file = st.selectbox(
                "Select File to Audit",
                file_options,
                format_func=lambda p: label_map.get(p, p),
                index=cur_idx,
                help="Choose which specific file in this repository to audit."
            )
            st.session_state.selected_file_for_audit = chosen_file
        else:
            typed_file = st.text_input(
                "Specific File Path (Relative)",
                value=st.session_state.selected_file_for_audit or "",
                placeholder="e.g. script.js or auth_service.py",
                help="Enter relative path within repository"
            )
            st.session_state.selected_file_for_audit = typed_file.strip() or None

    st.divider()

    # STEP 2: BYOK LLM PROVIDER & MODEL
    st.markdown("#### 2️⃣ Bring Your Own Key (BYOK)")
    
    saved_provider = saved_settings.get("provider", "")
    saved_model = saved_settings.get("model", "")
    saved_key = saved_settings.get("api_key", "")
    saved_endpoint = saved_settings.get("custom_endpoint", "")

    provider_options = [
        "Groq Cloud",
        "Google Gemini",
        "OpenAI",
        "Anthropic Claude",
        "DeepSeek",
        "Mistral AI",
        "OpenRouter",
        "Ollama / Local LLM",
        "Custom OpenAI-Compatible"
    ]

    default_prov_idx = 0
    if saved_provider in provider_options:
        default_prov_idx = provider_options.index(saved_provider)

    llm_provider = st.selectbox(
        "AI Provider",
        provider_options,
        index=default_prov_idx
    )

    # Rich model catalogs
    model_catalogs = {
        "Groq Cloud": [
            "llama-3.3-70b-versatile",
            "qwen/qwen3.6-27b",
            "openai/gpt-oss-20b",
            "llama-3.1-8b-instant",
            "mixtral-8x7b-32768",
            "deepseek-r1-distill-llama-70b",
            "gemma2-9b-it",
            "qwen-2.5-coder-32b",
            "✏️ Custom Model ID..."
        ],
        "Google Gemini": [
            "gemini-2.0-flash",
            "gemini-1.5-flash",
            "gemini-1.5-pro",
            "gemini-2.0-flash-lite",
            "✏️ Custom Model ID..."
        ],
        "OpenAI": [
            "gpt-4o",
            "gpt-4o-mini",
            "o3-mini",
            "o1",
            "o1-mini",
            "gpt-4-turbo",
            "gpt-3.5-turbo",
            "✏️ Custom Model ID..."
        ],
        "Anthropic Claude": [
            "claude-3-7-sonnet-20250219",
            "claude-3-5-sonnet-20241022",
            "claude-3-5-haiku-20241022",
            "claude-3-opus-20240229",
            "✏️ Custom Model ID..."
        ],
        "DeepSeek": [
            "deepseek-chat",
            "deepseek-reasoner",
            "✏️ Custom Model ID..."
        ],
        "Mistral AI": [
            "mistral-large-latest",
            "mistral-small-latest",
            "codestral-latest",
            "✏️ Custom Model ID..."
        ],
        "OpenRouter": [
            "deepseek/deepseek-r1",
            "deepseek/deepseek-chat",
            "anthropic/claude-3.5-sonnet",
            "meta-llama/llama-3.3-70b-instruct",
            "mistralai/mistral-large",
            "google/gemini-2.0-flash-001",
            "✏️ Custom Model ID..."
        ],
        "Ollama / Local LLM": [
            "qwen2.5-coder",
            "deepseek-r1",
            "llama3.2",
            "codellama",
            "✏️ Custom Model ID..."
        ],
        "Custom OpenAI-Compatible": [
            "custom-model",
            "✏️ Custom Model ID..."
        ]
    }

    catalog = model_catalogs.get(llm_provider, ["default"])
    default_model_idx = 0
    if saved_provider == llm_provider and saved_model:
        if saved_model in catalog:
            default_model_idx = catalog.index(saved_model)
        elif "✏️ Custom Model ID..." in catalog:
            default_model_idx = catalog.index("✏️ Custom Model ID...")

    selected_model_choice = st.selectbox(
        "Model",
        catalog,
        index=default_model_idx
    )

    if selected_model_choice == "✏️ Custom Model ID...":
        custom_val = saved_model if (saved_provider == llm_provider and saved_model not in catalog) else ""
        final_model_name = st.text_input("Model ID", value=custom_val, placeholder="e.g. meta-llama/llama-3.3-70b-instruct")
    else:
        final_model_name = selected_model_choice

    custom_endpoint_url = None
    if llm_provider in {"Custom OpenAI-Compatible", "Ollama / Local LLM"}:
        default_endpoint = "http://localhost:11434/v1" if llm_provider == "Ollama / Local LLM" else "http://localhost:8000/v1"
        endpoint_val = saved_endpoint if (saved_provider == llm_provider and saved_endpoint) else default_endpoint
        custom_endpoint_url = st.text_input("API Base URL", value=endpoint_val)

    # Lookup env key defaults
    env_map = {
        "Groq Cloud": "GROQ_API_KEY",
        "Google Gemini": "GEMINI_API_KEY",
        "OpenAI": "OPENAI_API_KEY",
        "Anthropic Claude": "ANTHROPIC_API_KEY",
        "DeepSeek": "DEEPSEEK_API_KEY",
        "Mistral AI": "MISTRAL_API_KEY",
        "OpenRouter": "OPENROUTER_API_KEY",
        "Ollama / Local LLM": "LOCAL_LLM_KEY",
        "Custom OpenAI-Compatible": "CUSTOM_LLM_KEY"
    }
    env_key = os.environ.get(env_map.get(llm_provider, ""), "")
    if saved_provider == llm_provider and saved_key:
        initial_key = saved_key
    else:
        initial_key = env_key

    if llm_provider == "Ollama / Local LLM" and not initial_key:
        initial_key = "ollama"

    byok_api_key = st.text_input(
        f"{llm_provider} API Key",
        type="password",
        value=initial_key,
        placeholder="Enter your personal key...",
        help="Used strictly in-memory during this session unless you click 'Remember this'."
    )

    # REMEMBER THIS BUTTON & CONTROLS
    col_rem1, col_rem2 = st.columns([3, 2])
    with col_rem1:
        if st.button("💾 Remember this", use_container_width=True, help="Automatically remember and prefill this AI Provider, Model, and Key for future sessions"):
            if not byok_api_key.strip():
                st.warning("Please enter your API key first before remembering.", icon="⚠️")
            else:
                save_byok_settings(
                    provider=llm_provider,
                    model=final_model_name,
                    api_key=byok_api_key.strip(),
                    custom_endpoint=custom_endpoint_url or "",
                    github_url=github_url.strip() if not use_demo else "",
                    github_token=github_token.strip() if not use_demo else ""
                )
                st.toast("Saved! Your Repo, AI Provider, Model & Key are now remembered.", icon="💾")
                st.rerun()

    with col_rem2:
        if saved_settings.get("remembered") or saved_settings.get("api_key") or saved_settings.get("github_url"):
            if st.button("🗑️ Forget", use_container_width=True, help="Clear remembered settings and repo entry from disk"):
                clear_saved_byok_settings()
                st.toast("Remembered settings cleared.", icon="🗑️")
                st.rerun()

    is_currently_remembered = (
        saved_settings.get("provider") == llm_provider and
        saved_settings.get("model") == final_model_name and
        bool(saved_settings.get("api_key"))
    )
    if is_currently_remembered:
        st.caption("✨ *Auto-loaded from remembered configuration.*")

    step2_ready = bool(byok_api_key.strip())
    if step2_ready:
        st.success("✓ Key Configured", icon="🔑")
    else:
        st.caption("ℹ️ Paste your AI provider key above.")

    st.divider()

    # TRIGGER BUTTON
    can_trigger = step1_ready and step2_ready
    if st.session_state.audit_scope == "file" and st.session_state.selected_file_for_audit:
        short_file = os.path.basename(st.session_state.selected_file_for_audit)
        run_btn_label = f"🚀 Audit File: {short_file}"
    else:
        run_btn_label = "🚀 Run Codebase Audit (All Files)"

    trigger_analysis = st.button(
        run_btn_label,
        type="primary",
        use_container_width=True,
        disabled=not can_trigger
    )

    if not can_trigger:
        st.caption("🔒 Complete Step 1 and Step 2 above to unlock audit.")

# ================= AUDIT CONTROLLER =================
if trigger_analysis:
    # Automatically remember the previous entry of the GitHub repo URL
    if not use_demo and github_url.strip():
        save_github_url(github_url.strip(), github_token.strip())

    target_file_param = st.session_state.selected_file_for_audit if st.session_state.audit_scope == "file" else None
    action_desc = f"Analyzing '{target_file_param}'..." if target_file_param else "Cloning repository and analyzing codebase..."

    with st.spinner(f"{action_desc} Generating AI explainers and line-precision fixes..."):
        try:
            # Check if workspace already exists and matches current repo
            needs_clone = (
                not st.session_state.target_path
                or not os.path.exists(st.session_state.target_path)
                or (not use_demo and st.session_state.repo_display_name != github_url.strip())
                or (use_demo and st.session_state.repo_display_name != "demo_repos/vulnerable_sample")
            )

            if needs_clone:
                if st.session_state.target_path and "codesentinel_" in st.session_state.target_path:
                    cleanup_cloned_repo(st.session_state.target_path)
                
                if not use_demo:
                    clone_res = clone_github_repo(github_url, github_token=github_token)
                    scan_dir = clone_res["path"]
                    st.session_state.repo_display_name = github_url.strip()
                else:
                    scan_dir = get_offline_demo_path()
                    st.session_state.repo_display_name = "demo_repos/vulnerable_sample"

                st.session_state.target_path = scan_dir
                st.session_state.target_files = scan_target_files(scan_dir)
            else:
                scan_dir = st.session_state.target_path
                if not st.session_state.target_files:
                    st.session_state.target_files = scan_target_files(scan_dir)

            results = analyze_repository(scan_dir, target_file=target_file_param)
            st.session_state.analysis_results = results
            st.session_state.active_remediations = {}
            if target_file_param:
                st.toast(f"Audit for '{target_file_param}' completed!", icon="📄")
            else:
                st.toast("Repository audit completed successfully!", icon="🛡️")

        except Exception as e:
            st.error(f"Audit failed: {str(e)}")

# ================= WELCOME SCREEN (WHEN EMPTY) =================
if not st.session_state.analysis_results:
    # 1. Hero Header & Value Proposition
    st.markdown("""
    <div class="hero-container">
        <div class="hero-badge">
            <span class="pulse-dot" style="color: #6366f1;"></span>
            <span style="font-size: 0.78rem; font-weight: 800; letter-spacing: 0.08em; color: #a5b4fc; text-transform: uppercase;">
                Autonomous SAST • AST Code Quality • Multi-LLM Defense
            </span>
        </div>
        <h1 class="hero-title">
            Code Sentinel AI
        </h1>
        <p class="hero-sub">
            Enterprise-grade static security analysis and AST logic auditing with verified, drop-in before/after AI refactorings for entire repositories and individual source files.
        </p>
        <div class="capability-chips">
            <span class="cap-chip">🛡️ 15+ Vulnerability Vectors</span>
            <span class="cap-chip">⚡ 5ms Sub-Second AST Engine</span>
            <span class="cap-chip">🤖 9 LLM BYOK Providers</span>
            <span class="cap-chip">🎯 Line-Precision Code Patches</span>
            <span class="cap-chip">📁 Multi-Language SAST</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ================= DIRECT CODE PASTE & INSTANT AUDIT TAB =================
    with st.expander("⚡ **Direct Code Paste & Instant Audit** (Click to Expand)", expanded=bool(st.session_state.get("pasted_code_content"))):
        st.markdown("""
        <div style="font-size: 0.92rem; color: #cbd5e1; margin-bottom: 14px; line-height: 1.55;">
            Paste any raw source code snippet below to perform instant <strong>0–100 Health Scoring</strong>, <strong>AST Logic & Maintainability validation</strong>, <strong>CWE security vulnerability detection</strong>, <strong>~60-word explainers</strong>, and <strong>AI-generated drop-in refactored code</strong>.
        </div>
        """, unsafe_allow_html=True)

        # Determine current code content for auto language detection
        raw_code = st.session_state.get("pasted_code_textarea") or st.session_state.get("pasted_code_content", "")
        detected_info = detect_code_language(raw_code)

        col_p_cfg1, col_p_cfg2, col_p_cfg3 = st.columns([1.6, 1.5, 2.1])
        with col_p_cfg1:
            ext_map = {
                "✨ Auto-Detect": detected_info["extension"],
                "Python (.py)": ".py",
                "JavaScript (.js)": ".js",
                "TypeScript (.ts)": ".ts",
                "HTML (.html)": ".html",
                "Java (.java)": ".java",
                "C / C++ (.cpp)": ".cpp",
                "Go (.go)": ".go"
            }
            chosen_lang = st.selectbox(
                "Code Language", 
                list(ext_map.keys()), 
                index=0, 
                key="paste_lang_select",
                help="Auto-detects language and syntax rules from your pasted code, or select manually to override."
            )
            
            if chosen_lang == "✨ Auto-Detect":
                effective_ext = detected_info["extension"]
                effective_label = detected_info["label"]
                if raw_code.strip():
                    st.markdown(f"""
                    <div style="margin-top: -6px; margin-bottom: 8px;">
                        <span style="font-size: 0.74rem; font-weight: 800; color: #34d399; background: rgba(16, 185, 129, 0.14); border: 1px solid rgba(16, 185, 129, 0.35); padding: 2px 9px; border-radius: 6px; letter-spacing: 0.03em;">
                            ✨ Auto-Detected: {detected_info['label']}
                        </span>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.caption("✨ Auto-detects upon paste")
            else:
                effective_ext = ext_map[chosen_lang]
                effective_label = chosen_lang
                st.markdown(f"""
                <div style="margin-top: -6px; margin-bottom: 8px;">
                    <span style="font-size: 0.74rem; font-weight: 700; color: #94a3b8; background: rgba(148, 163, 184, 0.12); border: 1px solid rgba(148, 163, 184, 0.25); padding: 2px 9px; border-radius: 6px;">
                        🔧 Manual Override: {chosen_lang}
                    </span>
                </div>
                """, unsafe_allow_html=True)

        with col_p_cfg2:
            default_fname = f"snippet{effective_ext}"
            existing_fname = st.session_state.get("pasted_code_filename", "")
            if not existing_fname or existing_fname.startswith("snippet."):
                current_fname_val = default_fname
            else:
                current_fname_val = existing_fname

            snippet_filename = st.text_input(
                "Target Filename (Optional)", 
                value=current_fname_val, 
                key="paste_filename_input",
                placeholder=default_fname,
                help="Optional. Automatically syncs with detected language. Leave as default."
            )
            if not snippet_filename.strip():
                snippet_filename = default_fname
            st.session_state.pasted_code_filename = snippet_filename

        with col_p_cfg3:
            st.write("")
            st.write("")
            c_btn_sample, c_btn_clear = st.columns(2)
            with c_btn_sample:
                if st.button("⚡ Load Sample", use_container_width=True, help="Load a pre-configured vulnerable Python code snippet"):
                    st.session_state.pasted_code_content = '''import sqlite3
import hashlib

def login_user(username, password):
    # Hardcoded sensitive API secret
    API_KEY = "sk-live-9876543210abcdef9876543210abcdef"
    
    # Insecure MD5 hashing algorithm
    hashed_pwd = hashlib.md5(password.encode()).hexdigest()
    
    # Critical: SQL Injection via string formatting
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT id, role FROM users WHERE username = '{username}' AND pwd = '{hashed_pwd}'"
    cursor.execute(query)
    
    try:
        user = cursor.fetchone()
        return user
    except:
        # Suppressed exception error (except: pass)
        pass

def execute_dynamic(user_input):
    # Critical: Arbitrary dynamic code execution vulnerability
    return eval(user_input)
'''
                    st.session_state.pasted_code_filename = "snippet.py"
                    if "pasted_code_textarea" in st.session_state:
                        st.session_state["pasted_code_textarea"] = st.session_state.pasted_code_content
                    st.rerun()

            with c_btn_clear:
                if st.button("🗑️ Clear", use_container_width=True, help="Clear text area"):
                    st.session_state.pasted_code_content = ""
                    st.session_state.pasted_code_filename = "snippet.py"
                    if "pasted_code_textarea" in st.session_state:
                        st.session_state["pasted_code_textarea"] = ""
                    st.rerun()

        pasted_code = st.text_area(
            "Paste Your Code Here",
            value=st.session_state.get("pasted_code_content", ""),
            height=320,
            placeholder="Paste any raw source code snippet here (Python, JS, TS, Go, Java, C++, HTML)...\n\nLanguage is automatically detected upon pasting!",
            key="pasted_code_textarea",
            help="Paste any source code snippet. Language is auto-detected and indentation is preserved."
        )
        st.session_state.pasted_code_content = pasted_code

        c_act_info, c_act_btn = st.columns([2.5, 1.5])
        with c_act_info:
            if byok_api_key.strip():
                st.caption(f"🤖 **AI Engine:** Using `{llm_provider}` (`{final_model_name}`) for drop-in patch generation.")
            else:
                st.caption("⚡ **Engine Mode:** Offline Heuristic Engine active (Configure API key in sidebar for multi-LLM fixes).")

        with c_act_btn:
            btn_audit_pasted = st.button("🚀 Analyze & Audit Pasted Code", type="primary", use_container_width=True)

        if btn_audit_pasted:
            if not pasted_code.strip():
                st.warning("Please paste source code into the text area before initiating audit.", icon="⚠️")
            else:
                # Resolve final language detection and filename
                if chosen_lang == "✨ Auto-Detect":
                    final_detect = detect_code_language(pasted_code)
                    active_ext = final_detect["extension"]
                    active_label = final_detect["label"]
                    if not snippet_filename.strip() or snippet_filename.startswith("snippet."):
                        safe_fname = f"snippet{active_ext}"
                    else:
                        safe_fname = os.path.basename(snippet_filename.strip())
                else:
                    active_ext = ext_map[chosen_lang]
                    active_label = chosen_lang
                    safe_fname = os.path.basename(snippet_filename.strip()) or f"snippet{active_ext}"

                with st.spinner(f"Analyzing {active_label} code ({safe_fname}) for vulnerabilities, AST logic debt, and complexity..."):
                    try:
                        # Clean up previous temporary snippet directory if present
                        if st.session_state.target_path and "codesentinel_" in st.session_state.target_path:
                            cleanup_cloned_repo(st.session_state.target_path)

                        # Create fresh isolated snippet workspace
                        snippet_dir = tempfile.mkdtemp(prefix="codesentinel_snippet_")
                        full_snippet_path = os.path.join(snippet_dir, safe_fname)
                        with open(full_snippet_path, "w", encoding="utf-8") as f:
                            f.write(pasted_code)

                        # Execute full static analysis
                        results = analyze_repository(snippet_dir, target_file=safe_fname)

                        # Update session state
                        st.session_state.target_path = snippet_dir
                        st.session_state.target_files = scan_target_files(snippet_dir)
                        st.session_state.repo_display_name = f"Pasted Snippet ({safe_fname})"
                        st.session_state.audit_scope = "file"
                        st.session_state.selected_file_for_audit = safe_fname
                        st.session_state.analysis_results = results
                        st.session_state.active_remediations = {}
                        st.toast(f"Pasted {active_label} analyzed: Health Score {results['summary']['health_score']}/100!", icon="🛡️")
                        st.rerun()
                    except Exception as ex:
                        st.error(f"Failed to analyze pasted code: {ex}")

    st.write("")

    # 2. Quick-Launch Command Center Card
    st.markdown("""
    <div class="quick-launch-card">
        <div style="position: absolute; top: 0; left: 0; right: 0; height: 3px; background: linear-gradient(90deg, #6366f1, #06b6d4, #10b981);"></div>
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px; margin-bottom: 20px;">
            <div style="text-align: left; max-width: 600px;">
                <div style="font-size: 1.35rem; font-weight: 800; color: #f8fafc; letter-spacing: -0.01em;">
                    ⚡ Ready to Audit Your Codebase?
                </div>
                <div style="font-size: 0.92rem; color: #94a3b8; margin-top: 4px; line-height: 1.55;">
                    Test drive the detection engine on our preloaded vulnerable codebase with 1-click, or connect your GitHub repository in the sidebar.
                </div>
            </div>
            <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
                <span style="font-size: 0.78rem; font-weight: 700; color: #10b981; background: rgba(16, 185, 129, 0.14); border: 1px solid rgba(16, 185, 129, 0.35); padding: 5px 14px; border-radius: 20px;">
                    ✓ In-Memory Analysis
                </span>
                <span style="font-size: 0.78rem; font-weight: 700; color: #38bdf8; background: rgba(56, 189, 248, 0.14); border: 1px solid rgba(56, 189, 248, 0.35); padding: 5px 14px; border-radius: 20px;">
                    ✓ Zero Data Retention
                </span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # 1-Click Launch Action
    ql_col1, ql_col2, ql_col3 = st.columns([1, 2.4, 1])
    with ql_col2:
        if st.button("⚡ Launch 1-Click Test Drive (Demo Codebase)", use_container_width=True, type="primary", help="Immediately run full AST and SAST audit on preloaded vulnerable sample"):
            demo_path = get_offline_demo_path()
            st.session_state.target_path = demo_path
            st.session_state.repo_display_name = "demo_repos/vulnerable_sample"
            st.session_state.target_files = scan_target_files(demo_path)
            st.session_state.analysis_results = analyze_repository(demo_path)
            st.session_state.active_remediations = {}
            st.rerun()

    st.write("")

    # 3. Interactive Live Remediation Preview Showcase
    st.markdown("""
    <div style="margin: 28px 0 16px 0;">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; margin-bottom: 12px;">
            <div>
                <div style="font-size: 1.25rem; font-weight: 800; color: #f8fafc; letter-spacing: -0.01em;">
                    🔍 Live Detection & AI Remediation Preview
                </div>
                <div style="font-size: 0.88rem; color: #94a3b8;">
                    Inspect how Code Sentinel AI identifies critical flaws, flags line numbers, and generates copy-paste drop-in patches:
                </div>
            </div>
            <span style="font-size: 0.76rem; font-weight: 800; color: #f87171; background: rgba(239, 68, 68, 0.16); border: 1px solid rgba(239, 68, 68, 0.35); padding: 4px 14px; border-radius: 20px; text-transform: uppercase;">
                🔴 CRITICAL CWE-89
            </span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    prev_c1, prev_c2 = st.columns(2)
    with prev_c1:
        st.markdown("""
        <div class="code-panel-header orig-header">
            <div class="code-panel-title">
                <span class="indicator-dot dot-orig"></span>
                <span>BEFORE CODE (FLAWED)</span>
            </div>
            <span class="diff-badge-del">- Line 31</span>
        </div>
        """, unsafe_allow_html=True)
        st.code("""# ❌ Raw f-string interpolation allows SQL Injection
query = f"SELECT * FROM users WHERE user = '{user}'"
cursor.execute(query)""", language="python")

    with prev_c2:
        st.markdown("""
        <div class="code-panel-header refac-header">
            <div class="code-panel-title">
                <span class="indicator-dot dot-refac"></span>
                <span>AFTER CODE (REFACTORED)</span>
            </div>
            <span class="diff-badge-add">+ Lines 31-32</span>
        </div>
        """, unsafe_allow_html=True)
        st.code("""# ✅ Parameterized query eliminates SQL injection vulnerability
query = "SELECT * FROM users WHERE user = %s"
cursor.execute(query, (user,))""", language="python")

    st.markdown("""
    <div class="explainer-box" style="margin-top: 4px; margin-bottom: 32px;">
        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;">
            <span style="color: #fbbf24; font-size: 1.05rem;">💡</span>
            <span style="color: #fbbf24; font-weight: 800; font-size: 0.82rem; letter-spacing: 0.06em; text-transform: uppercase;">
                Why this is problematic (~60-Word Explainer)
            </span>
        </div>
        <div style="color: #cbd5e1; font-size: 0.93rem; line-height: 1.65;">
            Direct f-string formatting interpolates untrusted user input directly into the SQL query buffer. Attackers can inject arbitrary SQL fragments (e.g. <code>' OR '1'='1</code>) to bypass authentication or dump database tables. Parameterized query placeholders enforce strict separation between code execution instructions and untrusted user data.
        </div>
    </div>
    """, unsafe_allow_html=True)

    # 4. Feature Architecture Grid (2x2 Balanced Cards)
    st.markdown("""
    <div style="margin-bottom: 16px;">
        <div style="font-size: 1.25rem; font-weight: 800; color: #f8fafc; letter-spacing: -0.01em;">
            🛠️ Comprehensive Engine Capabilities
        </div>
        <div style="font-size: 0.88rem; color: #94a3b8;">
            Deep code intelligence across security, maintainability, performance, and multi-model AI refactoring:
        </div>
    </div>
    """, unsafe_allow_html=True)

    grid_r1_c1, grid_r1_c2 = st.columns(2)
    with grid_r1_c1:
        st.markdown("""
        <div class="feature-grid-card" style="border-top: 3px solid #ef4444;">
            <div>
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px;">
                    <span style="font-size: 1.8rem;">🛡️</span>
                    <span style="font-size: 0.72rem; font-weight: 800; color: #f87171; background: rgba(239, 68, 68, 0.12); padding: 3px 10px; border-radius: 12px; border: 1px solid rgba(239, 68, 68, 0.3);">SAST & CWE</span>
                </div>
                <h4 style="margin: 0 0 8px 0; font-size: 1.15rem; font-weight: 800; color: #f8fafc;">Deep SAST Security Defense</h4>
                <p style="color: #94a3b8; font-size: 0.9rem; line-height: 1.6; margin: 0;">
                    Flags critical vulnerabilities before production: SQL Injection, Arbitrary Code Execution (<code>eval</code>), Hardcoded Credentials & Private RSA Keys, Insecure MD5 Hashing, and Insecure Network Requests.
                </p>
            </div>
            <div style="margin-top: 14px; font-size: 0.78rem; font-weight: 700; color: #ef4444;">
                Bandit Engine • Multi-Language Heuristics
            </div>
        </div>
        """, unsafe_allow_html=True)

    with grid_r1_c2:
        st.markdown("""
        <div class="feature-grid-card" style="border-top: 3px solid #f59e0b;">
            <div>
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px;">
                    <span style="font-size: 1.8rem;">⚡</span>
                    <span style="font-size: 0.72rem; font-weight: 800; color: #fbbf24; background: rgba(245, 158, 11, 0.12); padding: 3px 10px; border-radius: 12px; border: 1px solid rgba(245, 158, 11, 0.3);">AST ENGINE</span>
                </div>
                <h4 style="margin: 0 0 8px 0; font-size: 1.15rem; font-weight: 800; color: #f8fafc;">AST Logic & Maintainability</h4>
                <p style="color: #94a3b8; font-size: 0.9rem; line-height: 1.6; margin: 0;">
                    Detects hidden code smells and logic debt: bare <code>except:</code> clauses, suppressed errors (<code>except: pass</code>), high cyclomatic complexity (>10), unmanaged file resources, and unreachable dead code.
                </p>
            </div>
            <div style="margin-top: 14px; font-size: 0.78rem; font-weight: 700; color: #f59e0b;">
                Radon Complexity • Python AST Traversal
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.write("")

    grid_r2_c1, grid_r2_c2 = st.columns(2)
    with grid_r2_c1:
        st.markdown("""
        <div class="feature-grid-card" style="border-top: 3px solid #06b6d4;">
            <div>
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px;">
                    <span style="font-size: 1.8rem;">🤖</span>
                    <span style="font-size: 0.72rem; font-weight: 800; color: #38bdf8; background: rgba(6, 182, 212, 0.12); padding: 3px 10px; border-radius: 12px; border: 1px solid rgba(6, 182, 212, 0.3);">BYOK AI</span>
                </div>
                <h4 style="margin: 0 0 8px 0; font-size: 1.15rem; font-weight: 800; color: #f8fafc;">Universal Multi-LLM BYOK</h4>
                <p style="color: #94a3b8; font-size: 0.9rem; line-height: 1.6; margin: 0;">
                    Zero vendor lock-in. Connect your personal API key for Google Gemini, Groq Cloud, OpenAI, Anthropic Claude, DeepSeek, Mistral, OpenRouter, or local Ollama with persistent local session memory.
                </p>
            </div>
            <div style="margin-top: 14px; font-size: 0.78rem; font-weight: 700; color: #38bdf8;">
                Gemini • Claude • OpenAI • Groq • Ollama
            </div>
        </div>
        """, unsafe_allow_html=True)

    with grid_r2_c2:
        st.markdown("""
        <div class="feature-grid-card" style="border-top: 3px solid #10b981;">
            <div>
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px;">
                    <span style="font-size: 1.8rem;">🎯</span>
                    <span style="font-size: 0.72rem; font-weight: 800; color: #34d399; background: rgba(16, 185, 129, 0.12); padding: 3px 10px; border-radius: 12px; border: 1px solid rgba(16, 185, 129, 0.3);">DUAL SCOPE</span>
                </div>
                <h4 style="margin: 0 0 8px 0; font-size: 1.15rem; font-weight: 800; color: #f8fafc;">Single-File & Whole-Repo Scope</h4>
                <p style="color: #94a3b8; font-size: 0.9rem; line-height: 1.6; margin: 0;">
                    Switch seamlessly between evaluating the entire repository or isolating any single file (.py, .js, .ts, .html, .java). Yields file-isolated 0–100 health scoring and precise line-level replacement guides.
                </p>
            </div>
            <div style="margin-top: 14px; font-size: 0.78rem; font-weight: 700; color: #10b981;">
                Whole Repo • File-Isolated Health Score
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.write("")

    # 5. Security Pipeline Process Flow
    st.markdown("""
    <div style="margin: 28px 0 16px 0; text-align: center;">
        <div style="font-size: 1.15rem; font-weight: 800; color: #f8fafc; letter-spacing: -0.01em;">
            🚀 4-Stage Autonomous Defense Pipeline
        </div>
        <div style="font-size: 0.86rem; color: #94a3b8; margin-top: 4px;">
            How your code is inspected, scored, and refactored:
        </div>
    </div>
    """, unsafe_allow_html=True)

    p1, p2, p3, p4 = st.columns(4)
    with p1:
        st.markdown("""
        <div class="pipeline-step">
            <div style="font-size: 1.4rem;">1️⃣</div>
            <div>
                <div style="font-size: 0.86rem; font-weight: 800; color: #f1f5f9;">Connect Codebase</div>
                <div style="font-size: 0.76rem; color: #94a3b8;">GitHub or Demo Repo</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    with p2:
        st.markdown("""
        <div class="pipeline-step">
            <div style="font-size: 1.4rem;">2️⃣</div>
            <div>
                <div style="font-size: 0.86rem; font-weight: 800; color: #f1f5f9;">AST & SAST Audit</div>
                <div style="font-size: 0.76rem; color: #94a3b8;">15+ Security & Logic Rules</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    with p3:
        st.markdown("""
        <div class="pipeline-step">
            <div style="font-size: 1.4rem;">3️⃣</div>
            <div>
                <div style="font-size: 0.86rem; font-weight: 800; color: #f1f5f9;">Health Score (0–100)</div>
                <div style="font-size: 0.76rem; color: #94a3b8;">Grade A+ to Grade F</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    with p4:
        st.markdown("""
        <div class="pipeline-step">
            <div style="font-size: 1.4rem;">4️⃣</div>
            <div>
                <div style="font-size: 0.86rem; font-weight: 800; color: #f1f5f9;">AI Drop-In Patches</div>
                <div style="font-size: 0.76rem; color: #94a3b8;">Verified Refactorings</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.stop()

# ================= MAIN AUDIT RESULTS =================
summary = st.session_state.analysis_results["summary"]
findings = st.session_state.analysis_results["findings"]
score = summary["health_score"]

# Recompute fresh dark-mode native verbal rating dictionary
verbal_rating = get_codebase_verbal_rating(score)

rating_label = verbal_rating.get("label", "Audited")
rating_grade = verbal_rating.get("grade", "N/A")
rating_desc = verbal_rating.get("description", "")

# Unified status theme matching the dark obsidian background
grade_theme = {
    "A+": {
        "accent": "#10b981",
        "title_color": "#34d399",
        "border": "rgba(16, 185, 129, 0.45)",
        "card_bg": "linear-gradient(135deg, rgba(16, 185, 129, 0.12) 0%, rgba(20, 30, 48, 0.95) 45%, rgba(11, 17, 32, 0.98) 100%)",
        "glow": "rgba(16, 185, 129, 0.22)",
        "badge_bg": "linear-gradient(145deg, rgba(16, 185, 129, 0.2) 0%, rgba(11, 17, 32, 0.95) 100%)",
        "beam": "linear-gradient(90deg, #10b981 0%, #06b6d4 100%)",
    },
    "A": {
        "accent": "#38bdf8",
        "title_color": "#38bdf8",
        "border": "rgba(56, 189, 248, 0.45)",
        "card_bg": "linear-gradient(135deg, rgba(56, 189, 248, 0.12) 0%, rgba(20, 30, 48, 0.95) 45%, rgba(11, 17, 32, 0.98) 100%)",
        "glow": "rgba(56, 189, 248, 0.22)",
        "badge_bg": "linear-gradient(145deg, rgba(56, 189, 248, 0.2) 0%, rgba(11, 17, 32, 0.95) 100%)",
        "beam": "linear-gradient(90deg, #38bdf8 0%, #6366f1 100%)",
    },
    "B": {
        "accent": "#f59e0b",
        "title_color": "#fbbf24",
        "border": "rgba(245, 158, 11, 0.45)",
        "card_bg": "linear-gradient(135deg, rgba(245, 158, 11, 0.12) 0%, rgba(26, 32, 48, 0.95) 45%, rgba(11, 17, 32, 0.98) 100%)",
        "glow": "rgba(245, 158, 11, 0.22)",
        "badge_bg": "linear-gradient(145deg, rgba(245, 158, 11, 0.2) 0%, rgba(11, 17, 32, 0.95) 100%)",
        "beam": "linear-gradient(90deg, #f59e0b 0%, #f97316 100%)",
    },
    "C": {
        "accent": "#f97316",
        "title_color": "#fb923c",
        "border": "rgba(249, 115, 22, 0.45)",
        "card_bg": "linear-gradient(135deg, rgba(249, 115, 22, 0.14) 0%, rgba(26, 32, 48, 0.95) 45%, rgba(11, 17, 32, 0.98) 100%)",
        "glow": "rgba(249, 115, 22, 0.25)",
        "badge_bg": "linear-gradient(145deg, rgba(249, 115, 22, 0.2) 0%, rgba(11, 17, 32, 0.95) 100%)",
        "beam": "linear-gradient(90deg, #f97316 0%, #ef4444 100%)",
    },
    "F": {
        "accent": "#ef4444",
        "title_color": "#f87171",
        "border": "rgba(239, 68, 68, 0.45)",
        "card_bg": "linear-gradient(135deg, rgba(239, 68, 68, 0.14) 0%, rgba(26, 32, 48, 0.95) 45%, rgba(11, 17, 32, 0.98) 100%)",
        "glow": "rgba(239, 68, 68, 0.25)",
        "badge_bg": "linear-gradient(145deg, rgba(239, 68, 68, 0.2) 0%, rgba(11, 17, 32, 0.95) 100%)",
        "beam": "linear-gradient(90deg, #ef4444 0%, #f43f5e 100%)",
    }
}
theme = grade_theme.get(rating_grade, grade_theme["F"])
accent_color = theme["accent"]
border_color = theme["border"]

active_scope = summary.get("scope", "repo")
active_target_file = summary.get("target_file")

is_pasted_snippet = "Pasted Snippet" in (st.session_state.get("repo_display_name") or "")

# 0. SCOPE BANNER & SWITCHER (When in Single-File Mode)
if active_scope == "file" and active_target_file:
    col_sb1, col_sb2 = st.columns([3.8, 1.2])
    with col_sb1:
        if is_pasted_snippet:
            st.markdown(f"""
            <div style="background: rgba(139, 92, 246, 0.12); border: 1px solid rgba(139, 92, 246, 0.35); border-left: 5px solid #8b5cf6; border-radius: 12px; padding: 14px 20px; margin-bottom: 16px;">
                <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
                    <span style="font-size: 0.72rem; font-weight: 800; text-transform: uppercase; background: #8b5cf6; color: #ffffff; padding: 2px 10px; border-radius: 4px; letter-spacing: 0.06em;">
                        📝 DIRECT CODE PASTE AUDIT
                    </span>
                    <span style="font-size: 1.15rem; font-weight: 700; color: #f1f5f9;">
                        📄 <code>{active_target_file}</code>
                    </span>
                </div>
                <div style="font-size: 0.86rem; color: #94a3b8; margin-top: 4px;">
                    Instant AST logic validation, CWE security vulnerability audit, and AI drop-in refactoring performed directly on your pasted code.
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div style="background: rgba(59, 130, 246, 0.12); border: 1px solid rgba(59, 130, 246, 0.35); border-left: 5px solid #3b82f6; border-radius: 12px; padding: 14px 20px; margin-bottom: 16px;">
                <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
                    <span style="font-size: 0.72rem; font-weight: 800; text-transform: uppercase; background: #3b82f6; color: #ffffff; padding: 2px 10px; border-radius: 4px; letter-spacing: 0.06em;">
                        🎯 SPECIFIC FILE AUDIT
                    </span>
                    <span style="font-size: 1.15rem; font-weight: 700; color: #f1f5f9;">
                        📄 <code>{active_target_file}</code>
                    </span>
                </div>
                <div style="font-size: 0.86rem; color: #94a3b8; margin-top: 4px;">
                    Health score, criticality deductions, code review findings, and drop-in refactoring below are isolated specifically to this file.
                </div>
            </div>
            """, unsafe_allow_html=True)
    with col_sb2:
        if is_pasted_snippet:
            if st.button("✏️ Edit / New Snippet", use_container_width=True, help="Return to the code editor to paste or modify your snippet"):
                st.session_state.analysis_results = None
                st.session_state.active_remediations = {}
                st.rerun()
        else:
            if st.button("🌐 Entire Repo Audit", use_container_width=True, help="Run audit across all repository files"):
                with st.spinner("Analyzing all repository files..."):
                    st.session_state.audit_scope = "repo"
                    st.session_state.selected_file_for_audit = None
                    st.session_state.analysis_results = analyze_repository(st.session_state.target_path)
                    st.session_state.active_remediations = {}
                    st.rerun()

# 1. GORGEOUS HERO SCORECARD
if is_pasted_snippet:
    verdict_title = f"Snippet Health Verdict: {os.path.basename(active_target_file)}"
    target_desc = (
        f'<span style="color: #94a3b8; font-weight: 600;">Audited Snippet:</span> '
        f'<code style="color: #c084fc; background: rgba(15, 23, 42, 0.9); padding: 3px 10px; border-radius: 6px; border: 1px solid rgba(192, 132, 252, 0.35); font-family: \'JetBrains Mono\', monospace;">{active_target_file}</code>'
    )
elif active_scope == "file" and active_target_file:
    verdict_title = f"File Health Verdict: {os.path.basename(active_target_file)}"
    target_desc = (
        f'<span style="color: #94a3b8; font-weight: 600;">Target File:</span> '
        f'<code style="color: #38bdf8; background: rgba(15, 23, 42, 0.9); padding: 3px 10px; border-radius: 6px; border: 1px solid rgba(56, 189, 248, 0.35); font-family: \'JetBrains Mono\', monospace;">{active_target_file}</code>'
        f' &nbsp;<span style="opacity: 0.4;">|</span>&nbsp; '
        f'<span style="color: #94a3b8; font-weight: 600;">Repo:</span> '
        f'<code style="color: #34d399; background: rgba(15, 23, 42, 0.9); padding: 3px 10px; border-radius: 6px; border: 1px solid rgba(52, 211, 153, 0.35); font-family: \'JetBrains Mono\', monospace;">{st.session_state.repo_display_name}</code>'
    )
else:
    verdict_title = "Repository Health Verdict"
    target_desc = (
        f'<span style="color: #94a3b8; font-weight: 600;">Target Repo:</span> '
        f'<code style="color: #38bdf8; background: rgba(15, 23, 42, 0.9); padding: 3px 10px; border-radius: 6px; border: 1px solid rgba(56, 189, 248, 0.35); font-family: \'JetBrains Mono\', monospace;">{st.session_state.repo_display_name}</code>'
    )

st.markdown(f"""
<div class="hero-scorecard" style="border: 1px solid {theme['border']}; border-left: 6px solid {theme['accent']}; background: {theme['card_bg']}; box-shadow: 0 16px 40px -10px rgba(0, 0, 0, 0.6), 0 0 30px {theme['glow']};">
    <div style="position: absolute; top: 0; left: 0; right: 0; height: 3px; background: {theme['beam']};"></div>
    <div style="flex: 1; min-width: 320px;">
        <div style="display: inline-flex; align-items: center; gap: 8px; padding: 4px 14px; border-radius: 20px; background: rgba(15, 23, 42, 0.85); border: 1px solid {theme['accent']}44; margin-bottom: 10px;">
            <span style="width: 8px; height: 8px; border-radius: 50%; background: {theme['accent']}; box-shadow: 0 0 8px {theme['accent']};"></span>
            <span style="font-size: 0.78rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.08em; color: {theme['accent']};">
                {verdict_title}
            </span>
        </div>
        <h1 style="margin: 4px 0 12px 0; font-size: 2.35rem; font-weight: 900; letter-spacing: -0.02em; color: {theme['title_color']}; text-shadow: 0 2px 14px rgba(0, 0, 0, 0.6);">
            {rating_label}
        </h1>
        <p style="margin: 0; font-size: 1.05rem; line-height: 1.65; color: #f1f5f9; max-width: 780px; font-weight: 500; text-shadow: 0 1px 4px rgba(0, 0, 0, 0.6);">
            {rating_desc}
        </p>
        <div style="margin-top: 20px; width: 100%; max-width: 520px;">
            <div style="display: flex; justify-content: space-between; font-size: 0.78rem; font-weight: 800; color: #cbd5e1; margin-bottom: 6px; letter-spacing: 0.06em;">
                <span>HEALTH INTEGRITY INDEX</span>
                <span style="color: {theme['title_color']}; font-weight: 900; font-size: 0.88rem;">{score} / 100</span>
            </div>
            <div style="height: 8px; width: 100%; background: rgba(255, 255, 255, 0.08); border-radius: 6px; overflow: hidden; border: 1px solid rgba(255, 255, 255, 0.06);">
                <div style="height: 100%; width: {score}%; background: linear-gradient(90deg, {theme['accent']}, #06b6d4); box-shadow: 0 0 14px {theme['accent']};"></div>
            </div>
        </div>
        <div style="margin: 16px 0 0 0; font-size: 0.88rem; color: #cbd5e1; display: flex; gap: 12px; flex-wrap: wrap; align-items: center;">
            <span>{target_desc}</span>
            <span style="opacity: 0.4; color: #94a3b8;">•</span>
            <span style="background: rgba(15, 23, 42, 0.85); padding: 3px 12px; border-radius: 6px; border: 1px solid rgba(255, 255, 255, 0.1);">
                <strong style="color: #94a3b8;">AI Engine:</strong> <span style="color: #f1f5f9; font-weight: 600;">{llm_provider} ({final_model_name})</span>
            </span>
        </div>
    </div>
    <div class="score-badge" style="border: 2px solid {theme['border']}; background: {theme['badge_bg']}; box-shadow: 0 12px 30px rgba(0, 0, 0, 0.55), 0 0 25px {theme['glow']};">
        <div style="font-size: 3.4rem; font-weight: 900; line-height: 1; color: {theme['title_color']}; letter-spacing: -0.03em;">
            {score}<span style="font-size: 1.4rem; font-weight: 600; opacity: 0.7; color: #94a3b8;">/100</span>
        </div>
        <div style="font-size: 0.88rem; font-weight: 900; color: #ffffff; background: {theme['accent']}; padding: 4px 16px; border-radius: 20px; margin-top: 10px; letter-spacing: 0.06em; box-shadow: 0 4px 14px {theme['accent']}66;">
            GRADE {rating_grade}
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# 2. KEY METRIC PILLS (Balanced 5-Column KPI Cards)
m1, m2, m3, m4, m5 = st.columns(5)
with m1:
    st.markdown(f"""
    <div class="stat-kpi-card" style="border-top: 2px solid #ef4444;">
        <div class="kpi-header" style="color: #f87171;">
            <span>🔴 CRITICAL</span>
            <span style="font-size: 1rem;">🛡️</span>
        </div>
        <div class="kpi-val" style="color: #fca5a5;">{summary['critical']}</div>
        <div style="font-size: 0.72rem; color: #94a3b8;">High exploitability</div>
        <div class="kpi-bar" style="background: #ef4444;"></div>
    </div>
    """, unsafe_allow_html=True)
with m2:
    st.markdown(f"""
    <div class="stat-kpi-card" style="border-top: 2px solid #f97316;">
        <div class="kpi-header" style="color: #fb923c;">
            <span>🟠 HIGH RISK</span>
            <span style="font-size: 1rem;">⚠️</span>
        </div>
        <div class="kpi-val" style="color: #fdba74;">{summary['high']}</div>
        <div style="font-size: 0.72rem; color: #94a3b8;">Severe logic flaws</div>
        <div class="kpi-bar" style="background: #f97316;"></div>
    </div>
    """, unsafe_allow_html=True)
with m3:
    st.markdown(f"""
    <div class="stat-kpi-card" style="border-top: 2px solid #eab308;">
        <div class="kpi-header" style="color: #facc15;">
            <span>🟡 MEDIUM</span>
            <span style="font-size: 1rem;">⚡</span>
        </div>
        <div class="kpi-val" style="color: #fde047;">{summary['medium']}</div>
        <div style="font-size: 0.72rem; color: #94a3b8;">Debt & bottlenecks</div>
        <div class="kpi-bar" style="background: #eab308;"></div>
    </div>
    """, unsafe_allow_html=True)
with m4:
    st.markdown(f"""
    <div class="stat-kpi-card" style="border-top: 2px solid #3b82f6;">
        <div class="kpi-header" style="color: #60a5fa;">
            <span>🔵 LOW / INFO</span>
            <span style="font-size: 1rem;">🔍</span>
        </div>
        <div class="kpi-val" style="color: #93c5fd;">{summary['low']}</div>
        <div style="font-size: 0.72rem; color: #94a3b8;">Minor code smells</div>
        <div class="kpi-bar" style="background: #3b82f6;"></div>
    </div>
    """, unsafe_allow_html=True)
with m5:
    if active_scope == "file" and active_target_file:
        file_base = os.path.basename(active_target_file)
        st.markdown(f"""
        <div class="stat-kpi-card" style="border-top: 2px solid #38bdf8;">
            <div class="kpi-header" style="color: #38bdf8;">
                <span>🎯 AUDITED FILE</span>
                <span style="font-size: 1rem;">📄</span>
            </div>
            <div class="kpi-val" style="color: #7dd3fc; font-size: 1.35rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="{active_target_file}">{file_base}</div>
            <div style="font-size: 0.72rem; color: #94a3b8;">Target file scope</div>
            <div class="kpi-bar" style="background: #38bdf8;"></div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div class="stat-kpi-card" style="border-top: 2px solid #10b981;">
            <div class="kpi-header" style="color: #34d399;">
                <span>📁 SCANNED FILES</span>
                <span style="font-size: 1rem;">📦</span>
            </div>
            <div class="kpi-val" style="color: #86efac;">{len(st.session_state.target_files)}</div>
            <div style="font-size: 0.72rem; color: #94a3b8;">Full repository scope</div>
            <div class="kpi-bar" style="background: #10b981;"></div>
        </div>
        """, unsafe_allow_html=True)

# Quality & Logic Category Breakdown Strip
st.markdown(f"""
<div style="display: flex; gap: 12px; margin-top: 18px; flex-wrap: wrap;">
    <div style="padding: 8px 16px; border-radius: 10px; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.28); font-size: 0.85rem; font-weight: 700; color: #fca5a5; display: flex; align-items: center; gap: 8px;">
        <span>🛡️ Security Flaws</span>
        <span style="background: rgba(239, 68, 68, 0.25); padding: 2px 8px; border-radius: 12px; font-weight: 800;">{summary.get('security_count', 0)}</span>
    </div>
    <div style="padding: 8px 16px; border-radius: 10px; background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.28); font-size: 0.85rem; font-weight: 700; color: #93c5fd; display: flex; align-items: center; gap: 8px;">
        <span>🔍 Quality & Logic</span>
        <span style="background: rgba(59, 130, 246, 0.25); padding: 2px 8px; border-radius: 12px; font-weight: 800;">{summary.get('quality_count', 0)}</span>
    </div>
    <div style="padding: 8px 16px; border-radius: 10px; background: rgba(168, 85, 247, 0.1); border: 1px solid rgba(168, 85, 247, 0.28); font-size: 0.85rem; font-weight: 700; color: #d8b4fe; display: flex; align-items: center; gap: 8px;">
        <span>🧹 Maintainability Debt</span>
        <span style="background: rgba(168, 85, 247, 0.25); padding: 2px 8px; border-radius: 12px; font-weight: 800;">{summary.get('maintainability_count', 0)}</span>
    </div>
    <div style="padding: 8px 16px; border-radius: 10px; background: rgba(234, 179, 8, 0.1); border: 1px solid rgba(234, 179, 8, 0.28); font-size: 0.85rem; font-weight: 700; color: #fde047; display: flex; align-items: center; gap: 8px;">
        <span>⚡ Performance Bottlenecks</span>
        <span style="background: rgba(234, 179, 8, 0.25); padding: 2px 8px; border-radius: 12px; font-weight: 800;">{summary.get('performance_count', 0)}</span>
    </div>
</div>
""", unsafe_allow_html=True)

# Drill-Down / Quick File Switcher Bar
if st.session_state.target_files and len(st.session_state.target_files) > 1:
    with st.expander("🔍 **Audit a Specific File in this Repository**", expanded=(active_scope == "file")):
        st.caption("Select any individual file to isolate its health score, pinpoint issues, and generate before/after code fixes:")
        dd_c1, dd_c2 = st.columns([3.5, 1.5])
        with dd_c1:
            all_repo_files = [f["rel_path"] for f in st.session_state.target_files]
            lbl_dict = {f["rel_path"]: f.get("display_label", f["rel_path"]) for f in st.session_state.target_files}
            default_dd_idx = 0
            if active_target_file in all_repo_files:
                default_dd_idx = all_repo_files.index(active_target_file)
            dd_choice = st.selectbox(
                "Pick File to Audit",
                all_repo_files,
                format_func=lambda p: lbl_dict.get(p, p),
                index=default_dd_idx,
                label_visibility="collapsed",
                key="results_file_drilldown"
            )
        with dd_c2:
            if st.button("🎯 Audit Only This File", use_container_width=True, key="btn_drilldown_audit"):
                with st.spinner(f"Analyzing {dd_choice}..."):
                    st.session_state.audit_scope = "file"
                    st.session_state.selected_file_for_audit = dd_choice
                    st.session_state.analysis_results = analyze_repository(st.session_state.target_path, target_file=dd_choice)
                    st.session_state.active_remediations = {}
                    st.rerun()

st.write("")
st.divider()

# ================= 3. LINE-PRECISION CODE INSPECTOR & JUMP VIEWER =================
if findings:
    # Resolve active finding for line-precision focus
    active_finding = None
    if st.session_state.selected_finding_id:
        for f in findings:
            if f.get("id") == st.session_state.selected_finding_id:
                active_finding = f
                break
    if not active_finding:
        active_finding = findings[0]

    with st.expander("🎯 **Line-Precision Code Inspector & Jump Viewer**", expanded=True):
        active_file = active_finding.get("file", "")
        active_line = active_finding.get("line_no", active_finding.get("line", 1))
        active_title = active_finding.get("title", "")
        active_abs = active_finding.get("absolute_path", "")
        if not active_abs and st.session_state.target_path:
            active_abs = os.path.join(st.session_state.target_path, active_file)

        ins_c1, ins_c2 = st.columns([3, 2])
        with ins_c1:
            st.markdown(f"""
            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px; flex-wrap: wrap;">
                <span class="inspector-target-badge">
                    📍 Line {active_line} Focus
                </span>
                <span style="font-weight: 700; font-size: 1.05rem;">📄 <code>{active_file}</code></span>
            </div>
            <div style="color: #94a3b8; font-size: 0.9rem;">
                <strong>Selected Finding:</strong> {active_title}
            </div>
            """, unsafe_allow_html=True)
        with ins_c2:
            all_opts = [f"#{i+1}: {f.get('file')} : Line {f.get('line_no', f.get('line', 1))} — {f.get('title')[:35]}" for i, f in enumerate(findings)]
            cur_idx = 0
            for i, f in enumerate(findings):
                if f.get("id") == active_finding.get("id"):
                    cur_idx = i
                    break
            jump_pick = st.selectbox(
                "Jump to Flagged Line",
                range(len(all_opts)),
                format_func=lambda x: all_opts[x],
                index=cur_idx,
                label_visibility="collapsed"
            )
            if jump_pick != cur_idx:
                st.session_state.selected_finding_id = findings[jump_pick].get("id")
                st.rerun()

        # Render file context with line-number gutter and arrow indicator
        if os.path.exists(active_abs):
            try:
                with open(active_abs, "r", encoding="utf-8", errors="ignore") as f:
                    file_lines = f.readlines()
                total_l = len(file_lines)
                start_window = max(1, active_line - 10)
                end_window = min(total_l, active_line + 10)
                gutter_lines = []
                for ln in range(start_window, end_window + 1):
                    raw = file_lines[ln - 1].rstrip("\r\n")
                    if ln == active_line:
                        gutter_lines.append(f">> LINE {ln:4d} | {raw}   <-- [TARGET ISSUE: {active_title}]")
                    else:
                        gutter_lines.append(f"   LINE {ln:4d} | {raw}")

                f_ext = os.path.splitext(active_file)[1].lower()
                lang_tag = "python" if f_ext == ".py" else ("javascript" if f_ext in {".js", ".jsx"} else "text")

                st.markdown(f"""
                <div class="code-panel-header" style="background: rgba(15, 23, 42, 0.95); border: 1px solid rgba(99, 102, 241, 0.35); border-bottom: none; border-top-left-radius: 10px; border-top-right-radius: 10px;">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <div class="mac-dots">
                            <span class="mac-dot mac-red"></span>
                            <span class="mac-dot mac-yellow"></span>
                            <span class="mac-dot mac-green"></span>
                        </div>
                        <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; color: #94a3b8; font-weight: 600;">{active_file}</span>
                    </div>
                    <span style="font-size: 0.76rem; font-family: 'JetBrains Mono', monospace; color: #38bdf8; background: rgba(56, 189, 248, 0.15); padding: 2px 10px; border-radius: 6px; border: 1px solid rgba(56, 189, 248, 0.3);">
                        Lines {start_window}–{end_window} of {total_l}
                    </span>
                </div>
                """, unsafe_allow_html=True)
                st.code("\n".join(gutter_lines), language=lang_tag)
            except Exception as ex:
                st.caption(f"Could not load source file: {ex}")

st.write("")

# ================= 4. CATEGORIZED ISSUE TABS & DIFF DASHBOARD =================
c_header1, c_header2 = st.columns([3, 2])
with c_header1:
    st.markdown(f"### 📍 Detailed Findings & Refactoring Dashboard ({len(findings)})")
with c_header2:
    if st.button(
        f"⚡ Auto-Refactor All Issues with {llm_provider}",
        type="secondary",
        use_container_width=True,
        help="Debug all flagged issues and generate drop-in code snippets at once"
    ):
        with st.spinner(f"Refactoring all detected issues using {final_model_name or llm_provider}..."):
            prov_k = {
                "Groq Cloud": "groq",
                "Google Gemini": "gemini",
                "OpenAI": "openai",
                "Anthropic Claude": "anthropic",
                "DeepSeek": "deepseek",
                "Mistral AI": "mistral",
                "OpenRouter": "openrouter",
                "Ollama / Local LLM": "ollama",
                "Custom OpenAI-Compatible": "custom"
            }.get(llm_provider, "gemini")
            for itm in findings:
                f_id = itm.get("id", str(itm.get("line")))
                st.session_state.active_remediations[f_id] = generate_ai_remediation(
                    finding=itm,
                    provider=prov_k,
                    api_key=byok_api_key,
                    model_name=final_model_name,
                    custom_endpoint=custom_endpoint_url
                )
            st.toast("All issues refactored successfully!", icon="✅")
            st.rerun()

# Categorized Issue Tabs: All, Security, Quality/Maintainability
filter_tab_choice = st.radio(
    "Filter Categories",
    ["🎯 All Issues", "🛡️ Security Vulnerabilities", "🧹 Code Quality & Maintainability"],
    horizontal=True
)

# Filter logic
filtered_findings = findings
if filter_tab_choice == "🛡️ Security Vulnerabilities":
    filtered_findings = [f for f in findings if f.get("category") == "Security"]
elif filter_tab_choice == "🧹 Code Quality & Maintainability":
    filtered_findings = [f for f in findings if f.get("category") in {"Quality", "Maintainability", "Performance", "Functional"}]

if not filtered_findings:
    st.success("🎉 No issues detected in this filter category!")
else:
    for idx, item in enumerate(filtered_findings):
        severity = item.get("severity", "Low")
        sev_class = {
            "Critical": "chip-crit",
            "High": "chip-high",
            "Medium": "chip-med",
            "Low": "chip-low"
        }.get(severity, "chip-low")

        file_name = item.get("file", "unknown")
        line_num = item.get("line_no", item.get("line", 1))
        finding_id = item.get("id", str(idx))
        title = item.get("title", "Issue")

        # Auto-fetch remediation if not cached yet or if cached value contains obsolete comment placeholders
        cached_rem = st.session_state.active_remediations.get(finding_id)
        needs_fetch = (
            not cached_rem
            or "# Refactored defensive code" in cached_rem.get("refactored_code_snippet", "")
            or "verified fix for" in cached_rem.get("refactored_code_snippet", "").lower()
        )
        if needs_fetch:
            prov_k = {
                "Groq Cloud": "groq",
                "Google Gemini": "gemini",
                "OpenAI": "openai",
                "Anthropic Claude": "anthropic",
                "DeepSeek": "deepseek",
                "Mistral AI": "mistral",
                "OpenRouter": "openrouter",
                "Ollama / Local LLM": "ollama",
                "Custom OpenAI-Compatible": "custom"
            }.get(llm_provider, "gemini")

            st.session_state.active_remediations[finding_id] = generate_ai_remediation(
                finding=item,
                provider=prov_k,
                api_key=byok_api_key,
                model_name=final_model_name,
                custom_endpoint=custom_endpoint_url
            )

        rem = st.session_state.active_remediations.get(finding_id, {})
        preview_heuristic = _get_offline_heuristic_fix(item)
        explainer = item.get("explanation") or rem.get("explainer_60_words") or preview_heuristic.get("explainer_60_words") or title

        # Language syntax highlighting based on file extension
        ext = os.path.splitext(file_name)[1].lower()
        lang_map = {
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".html": "html",
            ".css": "css",
            ".py": "python",
            ".java": "java",
            ".json": "json",
            ".sql": "sql",
            ".sh": "bash",
            ".php": "php",
            ".go": "go",
            ".cpp": "cpp",
            ".c": "c",
            ".cs": "csharp",
        }
        syntax_lang = lang_map.get(ext, "python")

        # Category descriptor (zero technical linter jargon)
        category = item.get("category", "Quality")
        cat_info = {
            "Security": ("🛡️ Security Vulnerability", "rgba(239, 68, 68, 0.15)", "#f87171"),
            "Performance": ("⚡ Performance Bottleneck", "rgba(234, 179, 8, 0.15)", "#fbbf24"),
            "Maintainability": ("🧹 Maintainability Debt", "rgba(168, 85, 247, 0.15)", "#c084fc"),
            "Quality": ("🔍 Code Quality & Logic", "rgba(59, 130, 246, 0.15)", "#60a5fa"),
            "Functional": ("⚠️ Functional Bug", "rgba(245, 158, 11, 0.15)", "#fbbf24")
        }.get(category, ("🔍 Quality Issue", "rgba(148, 163, 184, 0.15)", "#94a3b8"))

        start_l = rem.get("start_line", line_num)
        end_l = rem.get("end_line", line_num)
        line_target = f"Lines {start_l}-{end_l}" if start_l != end_l else f"Line {start_l}"
        provider_badge = rem.get("ai_provider", f"{llm_provider} ({final_model_name})")

        card_accent = {
            "Critical": "#ef4444",
            "High": "#f97316",
            "Medium": "#f59e0b",
            "Low": "#3b82f6"
        }.get(severity, "#6366f1")

        card_glow = {
            "Critical": "rgba(239, 68, 68, 0.22)",
            "High": "rgba(249, 115, 22, 0.22)",
            "Medium": "rgba(245, 158, 11, 0.22)",
            "Low": "rgba(59, 130, 246, 0.22)"
        }.get(severity, "rgba(99, 102, 241, 0.22)")

        # Streamlined Finding Card Header
        st.markdown(f"""
        <div class="issue-card" style="border-left: 5px solid {card_accent}; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.35), 0 0 20px {card_glow};">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; margin-bottom: 12px;">
                <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
                    <span class="chip {sev_class}">
                        <span class="pulse-dot"></span>
                        {severity.upper()}
                    </span>
                    <span style="font-family: 'JetBrains Mono', monospace; font-weight: 600; font-size: 0.95rem; color: #f1f5f9; background: rgba(15, 23, 42, 0.8); padding: 4px 12px; border-radius: 8px; border: 1px solid rgba(255, 255, 255, 0.08);">
                        📄 {file_name} <span style="color: #38bdf8; margin-left: 4px;">: Line {line_num}</span>
                    </span>
                </div>
                <span style="font-size: 0.8rem; font-weight: 700; padding: 4px 14px; border-radius: 20px; background: {cat_info[1]}; color: {cat_info[2]}; border: 1px solid {cat_info[2]}40;">
                    {cat_info[0]}
                </span>
            </div>
            <div style="font-size: 1.15rem; font-weight: 700; margin-bottom: 14px; color: #f8fafc; letter-spacing: -0.01em;">
                {title}
            </div>
            <div class="explainer-box">
                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;">
                    <span style="color: #fbbf24; font-size: 1.05rem;">💡</span>
                    <span style="color: #fbbf24; font-weight: 800; font-size: 0.82rem; letter-spacing: 0.06em; text-transform: uppercase;">
                        Why this is problematic (~60-Word Explainer)
                    </span>
                </div>
                <div style="color: #cbd5e1; font-size: 0.95rem; line-height: 1.65;">
                    {explainer}
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Diff View Presentation Controls
        diff_col1, diff_col2, diff_col3 = st.columns([2.6, 1.2, 0.8])
        with diff_col1:
            st.markdown(f"""
            <div class="refactor-banner" style="margin: 0 0 10px 0;">
                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                    <span style="font-weight: 800; color: #10b981; font-size: 0.88rem; letter-spacing: 0.04em;">✅ AUTO-DEBUGGED BY {provider_badge.upper()}</span>
                </div>
                <div style="color: #e2e8f0; font-size: 0.9rem;">
                    📋 In <code>{rem.get('file', file_name)}</code>, replace <strong style="color: #34d399;">{line_target}</strong> with the replacement below:
                </div>
            </div>
            """, unsafe_allow_html=True)
        with diff_col2:
            diff_style = st.radio(
                "Diff Presentation",
                ["Side-by-Side Diff", "Unified Inline Diff"],
                horizontal=True,
                key=f"diff_style_{finding_id}",
                label_visibility="collapsed"
            )
        with diff_col3:
            if st.button("🎯 Focus Line", key=f"focus_btn_{finding_id}", use_container_width=True, help="Jump to this line in the code inspector"):
                st.session_state.selected_finding_id = finding_id
                st.rerun()

        # Extract before and after snippets
        before_code = (
            item.get("before_code")
            or rem.get("before_code")
            or rem.get("original_code_snippet")
            or item.get("highlighted_context")
            or item.get("context_snippet")
            or item.get("vulnerable_code")
            or ""
        )
        after_code = (
            item.get("after_code")
            or rem.get("after_code")
            or rem.get("refactored_code_snippet")
            or "# Refactored code"
        )

        # Side-by-Side vs Unified Diff
        if diff_style == "Side-by-Side Diff":
            c_diff1, c_diff2 = st.columns(2)
            with c_diff1:
                st.markdown(f"""
                <div class="code-panel-header orig-header">
                    <div class="code-panel-title">
                        <span class="indicator-dot dot-orig"></span>
                        <span>BEFORE CODE (FLAWED)</span>
                    </div>
                    <span class="diff-badge-del">- Line {line_num}</span>
                </div>
                """, unsafe_allow_html=True)
                st.code(before_code, language=syntax_lang)

            with c_diff2:
                st.markdown(f"""
                <div class="code-panel-header refac-header">
                    <div class="code-panel-title">
                        <span class="indicator-dot dot-refac"></span>
                        <span>AFTER CODE (REFACTORED)</span>
                    </div>
                    <span class="diff-badge-add">+ {line_target}</span>
                </div>
                """, unsafe_allow_html=True)
                st.code(after_code, language=syntax_lang)
        else:
            st.markdown(f"""
            <div class="code-panel-header" style="background: linear-gradient(90deg, rgba(99, 102, 241, 0.2) 0%, rgba(99, 102, 241, 0.08) 100%); border: 1px solid rgba(99, 102, 241, 0.35); border-bottom: none; color: #a5b4fc;">
                <div class="code-panel-title">
                    <div class="mac-dots">
                        <span class="mac-dot mac-red"></span>
                        <span class="mac-dot mac-yellow"></span>
                        <span class="mac-dot mac-green"></span>
                    </div>
                    <span>UNIFIED INLINE DIFF (BEFORE vs AFTER)</span>
                </div>
                <span style="font-size: 0.78rem; opacity: 0.9; font-family: 'JetBrains Mono', monospace; color: #38bdf8;">{file_name}:{line_target}</span>
            </div>
            """, unsafe_allow_html=True)
            before_lines = [f"- {l}" for l in before_code.splitlines()]
            after_lines = [f"+ {l}" for l in after_code.splitlines()]
            diff_text = (
                f"--- a/{file_name}:{line_num}\n"
                f"+++ b/{file_name}:{line_num}\n"
                + "\n".join(before_lines) + "\n"
                + "\n".join(after_lines)
            )
            st.code(diff_text, language="diff")

        # Changes Description Card (Where & What)
        where_val = rem.get("where_changed") or f"In '{rem.get('file', file_name)}' ({line_target})"
        what_val = rem.get("what_changed") or rem.get("suggested_fix") or "Applied defensive code refactoring to remediate the code flaw."

        st.markdown(f"""
        <div class="change-summary-card">
            <div class="change-item">
                <div class="change-tag tag-where">📍 WHERE CHANGES WERE MADE</div>
                <div class="change-detail">{where_val}</div>
            </div>
            <div class="change-item">
                <div class="change-tag tag-what">⚡ WHAT CHANGES WERE MADE</div>
                <div class="change-detail">{what_val}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        req_imports = rem.get("required_imports")
        if req_imports and req_imports.strip().lower() not in ["none", "none (already present)", "none (already imported)"]:
            st.info(f"📌 **Required Imports (Add to top of `{file_name}`):** `{req_imports}`")

        # Zero-error fallback: Safe full enclosing function
        if rem.get("safe_enclosing_function"):
            with st.expander("🛡️ View Safe Full Enclosing Function (Zero Side-Effects Alternative)", expanded=False):
                st.caption(f"To guarantee zero indentation mismatch and ensure neighboring functions remain completely unaffected, you can replace the entire enclosing function in `{file_name}`:")
                st.code(rem.get("safe_enclosing_function"), language=syntax_lang)

        # 4. Action Bar & Metadata Footer
        c_act1, c_act2, c_act3 = st.columns([2.8, 1.3, 0.9])
        with c_act1:
            st.markdown(f"""
            <div style="font-size: 0.86rem; color: #94a3b8; padding-top: 4px;">
                <strong style="color: #cbd5e1;">🛠️ Strategy:</strong> {rem.get('suggested_fix', 'Refactor logic with defensive programming.')}
            </div>
            """, unsafe_allow_html=True)
        with c_act2:
            std_val = rem.get('security_standard', 'CWE Quality Guideline')
            st.markdown(f"""
            <div style="font-size: 0.86rem; color: #94a3b8; padding-top: 4px;">
                <strong style="color: #cbd5e1;">🏷️ Standard:</strong> <code style="color: #38bdf8;">{std_val}</code>
            </div>
            """, unsafe_allow_html=True)
        with c_act3:
            if st.button("🔄 Re-Debug", key=f"re_debug_{finding_id}", use_container_width=True):
                with st.spinner(f"Re-debugging with {final_model_name or llm_provider}..."):
                    prov_k = {
                        "Groq Cloud": "groq",
                        "Google Gemini": "gemini",
                        "OpenAI": "openai",
                        "Anthropic Claude": "anthropic",
                        "DeepSeek": "deepseek",
                        "Mistral AI": "mistral",
                        "OpenRouter": "openrouter",
                        "Ollama / Local LLM": "ollama",
                        "Custom OpenAI-Compatible": "custom"
                    }.get(llm_provider, "gemini")

                    st.session_state.active_remediations[finding_id] = generate_ai_remediation(
                        finding=item,
                        provider=prov_k,
                        api_key=byok_api_key,
                        model_name=final_model_name,
                        custom_endpoint=custom_endpoint_url
                    )
                    st.rerun()

        st.divider()

# ================= EXPORT REPORT =================
if is_pasted_snippet:
    report_title = "# 🛡️ Code Sentinel AI — Pasted Code Audit Report"
    target_line_text = f"**Audited Snippet:** `{active_target_file}`"
elif active_scope == "file":
    report_title = "# 🛡️ Code Sentinel AI — Single File Audit Report"
    target_line_text = f"**Target File:** `{active_target_file}` (in `{st.session_state.repo_display_name}`)"
else:
    report_title = "# 🛡️ Code Sentinel AI — Repository Audit Report"
    target_line_text = f"**Repository:** `{st.session_state.repo_display_name}`"

report_lines = [
    report_title,
    target_line_text,
    f"**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    f"**Health Score:** {score}/100 ({rating_label})",
    f"**Issues:** {summary['total_issues']} (Critical: {summary['critical']}, High: {summary['high']}, Medium: {summary['medium']}, Low: {summary['low']})\n",
    f"## Executive Verdict",
    f"{rating_desc}\n",
    f"## Detailed Findings & 60-Word Explainers\n"
]

for item in findings:
    fid = item.get("id", "")
    rem = st.session_state.active_remediations.get(fid, {})
    exp = rem.get("explainer_60_words") or _get_offline_heuristic_fix(item).get("explainer_60_words") or item.get("title", "")
    report_lines.append(f"### [{item.get('severity')}] {item.get('file')} (Line {item.get('line')}): {item.get('title')}")
    report_lines.append(f"**60-Word Explainer:** {exp}\n")
    report_lines.append(f"```python\n# Vulnerable Code (Line {item.get('line')}):\n{item.get('vulnerable_code')}\n```\n")
    if rem.get("refactored_code_snippet"):
        start_l = rem.get("start_line", item.get("line"))
        end_l = rem.get("end_line", item.get("line"))
        report_lines.append(f"**AI Refactored Code (Replace Lines {start_l}–{end_l}):**\n")
        report_lines.append(f"```python\n{rem.get('refactored_code_snippet')}\n```\n")
        if rem.get("safe_enclosing_function"):
            report_lines.append(f"**Safe Full Enclosing Function (Zero Side-Effects):**\n")
            report_lines.append(f"```python\n{rem.get('safe_enclosing_function')}\n```\n")

dl_file_name = f"audit_report_{os.path.splitext(os.path.basename(active_target_file))[0]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md" if active_scope == "file" and active_target_file else f"audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

st.markdown("""
<div style="margin-top: 32px; padding: 22px 26px; border-radius: 16px; background: linear-gradient(145deg, rgba(16, 185, 129, 0.08) 0%, rgba(15, 23, 42, 0.6) 100%); border: 1px solid rgba(16, 185, 129, 0.25); text-align: center;">
    <div style="font-size: 1.15rem; font-weight: 700; color: #f1f5f9; margin-bottom: 6px;">📄 Export Comprehensive Security & Quality Report</div>
    <div style="font-size: 0.9rem; color: #94a3b8; margin-bottom: 16px;">Download the complete audit findings, line-by-line 60-word explainers, and refactored drop-in code patches in Markdown format.</div>
</div>
""", unsafe_allow_html=True)

st.download_button(
    label="📥 Download Full Audit Report (.md)",
    data="\n".join(report_lines),
    file_name=dl_file_name,
    mime="text/markdown",
    use_container_width=True
)



