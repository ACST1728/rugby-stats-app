# streamlit_app.py
import importlib
import streamlit as st

st.set_page_config(page_title="Rugby Stats v3y", layout="wide")

try:
    mod = importlib.import_module("rugby_stats_app_v3y")
    if hasattr(mod, "main"):
        mod.main()
    else:
        st.error("Could not find main() in rugby_stats_app_v3y.py")
except Exception as e:
    st.error(f"Failed to start app: {e}")
