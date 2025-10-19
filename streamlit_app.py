# streamlit_app.py (entrypoint for Streamlit Cloud)
import importlib
import streamlit as st

# Do NOT call st.set_page_config here to avoid duplicate calls.
# Let the main app module handle page config.
mod = importlib.import_module("rugby_stats_app_v3y")
if hasattr(mod, "main"):
    mod.main()
else:
    st.error("Could not find main() in rugby_stats_app_v3y.py")
