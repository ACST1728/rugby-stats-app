# streamlit_app.py — entrypoint with early page_config + safe first-time setup
import importlib, os, sqlite3, bcrypt
import streamlit as st

# 1) MUST be the first Streamlit command on the page
st.set_page_config(page_title="Rugby Stats v3y", layout="wide")

# 2) Avoid double-calling errors if the app calls set_page_config again
def _noop(*args, **kwargs):
    return None
st.set_page_config = _noop

DB_PATH = os.environ.get("RUGBY_DB_PATH", "rugby_stats.db")

@st.cache_resource
def _conn():
    # Thread-safe for Streamlit
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def _ensure_users_table(conn: sqlite3.Connection):
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            pass_hash BLOB NOT NULL,
            role TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
        );"""
    )
    conn.commit()

def _count_users(conn: sqlite3.Connection) -> int:
    try:
        cur = conn.execute("SELECT COUNT(*) FROM users")
        return int(cur.fetchone()[0])
    except sqlite3.OperationalError:
        return 0

def _user_exists(conn: sqlite3.Connection, username: str) -> bool:
    cur = conn.execute("SELECT 1 FROM users WHERE username=?", (username,))
    return cur.fetchone() is not None

def _create_admin(conn: sqlite3.Connection, username: str, password: str):
    ph = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    with conn:
        conn.execute(
            "INSERT INTO users(username, pass_hash, role, active) VALUES(?,?,?,1)",
            (username, ph, "admin")
        )

def first_time_setup():
    st.title("🔐 First-time Setup")
    st.write("No users found. Create your **first admin** to get started.")
    with st.form("create_admin"):
        u = st.text_input("Admin username", placeholder="e.g. coach_scott")
        p1 = st.text_input("Password", type="password")
        p2 = st.text_input("Confirm password", type="password")
        go = st.form_submit_button("Create admin")
        if go:
            if not u or not p1:
                st.error("Please enter a username and password.")
            elif p1 != p2:
                st.error("Passwords do not match.")
            else:
                try:
                    conn = _conn()
                    if _user_exists(conn, u):
                        st.error("That username already exists.")
                    else:
                        _create_admin(conn, u, p1)
                        st.success(f"Admin '{u}' created ✅")
                        st.session_state["_admin_created"] = True
                except Exception as e:
                    st.error(f"Failed to create admin: {e}")
    if st.session_state.get("_admin_created"):
        st.info("Admin created. Click **Continue** to launch the app.")
        if st.button("Continue"):
            st.rerun()

def main():
    conn = _conn()
    _ensure_users_table(conn)
    n = _count_users(conn)

    if n == 0:
        first_time_setup()
        return

    # Hand off to main app
    mod = importlib.import_module("rugby_stats_app_v3y")
    if hasattr(mod, "main"):
        mod.main()
    else:
        st.error("Could not find main() in rugby_stats_app_v3y.py")

if __name__ == "__main__":
    main()
