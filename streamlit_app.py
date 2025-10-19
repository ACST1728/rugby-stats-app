# streamlit_app.py — entrypoint with first-time setup + built-in Login/Logout
import importlib, os, sqlite3, bcrypt
import streamlit as st

# 1) Page config must be first Streamlit call
st.set_page_config(page_title="Rugby Stats v3y", layout="wide")

# Avoid duplicate set_page_config in the main app
def _noop(*args, **kwargs): return None
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

def _user_row(conn: sqlite3.Connection, username: str):
    cur = conn.execute("SELECT username, pass_hash, role, active FROM users WHERE username=?", (username,))
    r = cur.fetchone()
    if not r:
        return None
    return {"username": r[0], "pass_hash": r[1], "role": r[2], "active": int(r[3])}

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
                    if _user_row(conn, u):
                        st.error("That username already exists.")
                    else:
                        _create_admin(conn, u, p1)
                        st.success(f"Admin '{u}' created ✅")
                        st.session_state["_admin_created"] = True
                except Exception as e:
                    st.error(f"Failed to create admin: {e}")
    if st.session_state.get("_admin_created"):
        st.info("Admin created. Click **Continue** to go to login.")
        if st.button("Continue"):
            st.rerun()

def login_panel():
    st.sidebar.subheader("Login")
    u = st.sidebar.text_input("Username", key="__u")
    p = st.sidebar.text_input("Password", type="password", key="__p")
    if st.sidebar.button("Sign in"):
        conn = _conn()
        rec = _user_row(conn, u.strip())
        if rec and rec["active"] == 1 and bcrypt.checkpw(p.encode("utf-8"), rec["pass_hash"]):
            st.session_state["auth_user"] = rec["username"]
            st.session_state["auth_role"] = rec["role"]
            st.toast(f"Signed in as {rec['username']} ({rec['role']})", icon="✅")
            st.rerun()
        else:
            st.sidebar.error("Invalid username/password or inactive user")

def show_user_badge():
    u = st.session_state.get("auth_user")
    r = st.session_state.get("auth_role", "-")
    if u:
        with st.sidebar.expander("Account", expanded=True):
            st.write(f"**User:** {u}")
            st.write(f"**Role:** {r}")
            if st.button("Logout"):
                for k in ["auth_user", "auth_role"]:
                    st.session_state.pop(k, None)
                st.rerun()

def main():
    conn = _conn()
    _ensure_users_table(conn)
    if _count_users(conn) == 0:
        first_time_setup()
        return

    # If not logged in, show Login in sidebar and stop
    if not st.session_state.get("auth_user"):
        login_panel()
        st.title("Welcome")
        st.info("Please sign in using the sidebar to continue.")
        return

    show_user_badge()

    # Hand off to the main app
    mod = importlib.import_module("rugby_stats_app_v3y")
    if hasattr(mod, "main"):
        # Expose user in a conventional place the app can read
        st.session_state.setdefault("current_user", st.session_state["auth_user"])
        st.session_state.setdefault("current_role", st.session_state["auth_role"])
        mod.main()
    else:
        st.error("Could not find main() in rugby_stats_app_v3y.py")

if __name__ == "__main__":
    main()
