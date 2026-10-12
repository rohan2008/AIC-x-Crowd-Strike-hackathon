"""Scan view. Run: streamlit run scan_app.py   (needs OPENAI_API_KEY)"""
import os as _os, sys as _sys
_here = _os.path.dirname(_os.path.abspath(__file__))
for _p in (_here, _os.path.dirname(_here)):  # import the firewall library from the repo root
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
import pandas as pd
import streamlit as st

from agentfw import MODEL
from scanner import RUNS, flagged, scan_before_after, write_report

st.set_page_config(page_title="Agent scanner", layout="wide")

SEVERITY_COLORS = {
    "critical": "background-color: #d64545; color: white",
    "high": "background-color: #e8590c; color: white",
    "medium": "background-color: #f2c94c; color: black",
    "none": "background-color: #2f9e5b; color: white",
}

st.title("Pentest your AI agent")
st.caption("Replays every attack doc against the agent, scores how exposed it is, then re-runs with the firewall on.")
st.caption(f"Model: `{MODEL}` · {RUNS} runs per attack, firewall off and on (set RUNS to change)")

if st.button("Scan agent", type="primary", icon=":material/radar:", width="stretch"):
    with st.spinner("Running every attack against the model, firewall off then on..."):
        st.session_state.scan = scan_before_after()
        write_report(*st.session_state.scan)

if "scan" not in st.session_state:
    st.stop()

before, after = st.session_state.scan

# ---------- score ----------
with st.container(horizontal=True):
    st.metric("Exposure, firewall off", f"{before['score']}/100", border=True)
    st.metric(
        "Exposure, firewall on", f"{after['score']}/100",
        delta=after["score"] - before["score"], delta_color="inverse", border=True,
    )
    st.metric("Benign doc never blocked (firewall on)", "Yes" if after["control_ok"] else "No", border=True)
st.progress(before["score"] / 100, text=f"Exposure before fix: {before['score']}/100")

# ---------- findings ----------
st.subheader("Findings")
rows = pd.DataFrame([
    {
        "Attack": b["attack"],
        "Technique": b["technique"],
        "Key leaked (off)": f"{b['leaked']}/{before['runs']}",
        "Key leaked (on)": f"{a['leaked']}/{after['runs']}",
        "Worst run (off)": b["severity"],
        "Worst run (on)": a["severity"],
        "Secret sent to": ", ".join(b["sent_to"]) or "-",
        "Detector": flagged(b),
    }
    for b, a in zip(before["results"], after["results"])
])
styled = rows.style.map(lambda s: SEVERITY_COLORS.get(s, ""), subset=["Worst run (off)", "Worst run (on)"])
st.dataframe(styled, hide_index=True, alt="Scan findings by attack, colored by severity")

# ---------- before / after ----------
st.subheader("Recommended fix: turn on the firewall")
chart = pd.DataFrame(
    {"Exposure score": [before["score"], after["score"]]}, index=["Firewall off", "Firewall on"]
)
st.bar_chart(chart, horizontal=True, color="#3b5bdb", alt="Exposure score before and after the firewall")

with st.expander("Detector reasons (firewall off)"):
    for r in before["results"]:
        for i, run in enumerate(r["runs"], 1):
            for d in run["detections"]:
                st.write(f"**{r['attack']}** run {i}, {d['severity']}: {d['reason']}")

st.caption("Full report written to scan_report.md")
