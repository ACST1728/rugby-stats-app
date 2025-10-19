# streamlit_app.py — entrypoint with login + admin user management + safe setup
import importlib, os, sqlite3, bcrypt
import streamlit as st

# 1) Page config must be the first Streamlit call
st.set_page_config(page_title="Rugby Stats v3y", layout="wide")

# Avoid duplicate set_page_config in the main app
def _noop(*args, **kwargs): return None
st.set_page_config = _noop

DB_PATH = os.environ.get("RUGBY_DB_PATH", "/mount/data/rugby_stats.db")
ROLES = ["admin", "editor", "viewer"]

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

def _list_users(conn: sqlite3.Connection):
    cur = conn.execute("SELECT username, role, active FROM users ORDER BY username")
    return [ {"username":u, "role":r, "active":int(a)} for (u,r,a) in cur.fetchall() ]

def _create_user(conn: sqlite3.Connection, username: str, password: str, role: str, active: int = 1):
    ph = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    with conn:
        conn.execute(
            "INSERT INTO users(username, pass_hash, role, active) VALUES(?,?,?,?)",
            (username, ph, role, int(active))
        )

def _create_admin(conn: sqlite3.Connection, username: str, password: str):
    _create_user(conn, username, password, role="admin", active=1)

def _set_role(conn: sqlite3.Connection, username: str, role: str):
    with conn:
        conn.execute("UPDATE users SET role=? WHERE username=?", (role, username))

def _set_active(conn: sqlite3.Connection, username: str, active: int):
    with conn:
        conn.execute("UPDATE users SET active=? WHERE username=?", (int(active), username))

def _reset_password(conn: sqlite3.Connection, username: str, password: str):
    ph = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    with conn:
        conn.execute("UPDATE users SET pass_hash=? WHERE username=?", (ph, username))

def _delete_user(conn: sqlite3.Connection, username: str):
    with conn:
        conn.execute("DELETE FROM users WHERE username=?", (username,))

# ---------------- UI helpers ----------------

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
                        st.session_state["auth_user"] = u
                        st.session_state["auth_role"] = "admin"
                        st.experimental_rerun()
                except Exception as e:
                    st.error(f"Failed to create admin: {e}")

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
            st.experimental_rerun()
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
                st.experimental_rerun()

def user_management_panel():
    st.title("👤 User Management (Admin)")
    conn = _conn()

    st.subheader("Add User")
    with st.form("add_user"):
        col1, col2, col3 = st.columns([2,2,1])
        with col1:
            nu = st.text_input("Username", placeholder="firstname_surname")
        with col2:
            np = st.text_input("Password", type="password")
        with col3:
            nr = st.selectbox("Role", ROLES, index=1)
        create = st.form_submit_button("Create")
        if create:
            if not nu or not np:
                st.error("Username and password required.")
            elif _user_row(conn, nu):
                st.error("User already exists.")
            else:
                _create_user(conn, nu, np, nr, active=1)
                st.success(f"User '{nu}' created as {nr}")
                st.experimental_rerun()

    st.subheader("Existing Users")
    users = _list_users(conn)
    if not users:
        st.info("No users yet.")
        return

    for rec in users:
        with st.expander(f\"{rec['username']}  —  {rec['role']}  —  {'Active' if rec['active'] else 'Inactive'}\", expanded=False):
            c1, c2, c3, c4 = st.columns([1,1,1,1])
            with c1:
                new_role = st.selectbox("Role", ROLES, index=ROLES.index(rec['role']), key=f"role_{rec['username']}")
                if st.button("Update role", key=f"btn_role_{rec['username']}"):
                    _set_role(conn, rec["username"], new_role)
                    st.success("Role updated")
                    st.experimental_rerun()
            with c2:
                act = st.toggle("Active", value=bool(rec["active"]), key=f"act_{rec['username']}")
                if st.button("Apply active", key=f"btn_act_{rec['username']}"):
                    _set_active(conn, rec["username"], int(act))
                    st.success("Active state updated")
                    st.experimental_rerun()
            with c3:
                npw = st.text_input("New password", type="password", key=f"pwd_{rec['username']}")
                if st.button("Reset password", key=f"btn_pwd_{rec['username']}"):
                    if not npw:
                        st.error("Enter a new password first.")
                    else:
                        _reset_password(conn, rec["username"], npw)
                        st.success("Password reset")
            with c4:
                if st.button("Delete user", key=f"del_{rec['username']}"):
                    if rec["username"] == st.session_state.get("auth_user"):
                        st.error("You cannot delete the account you are logged in with.")
                    else:
                        _delete_user(conn, rec["username"])
                        st.warning("User deleted")
                        st.experimental_rerun()

def change_my_password_panel():
    st.title("🔑 Change My Password")
    conn = _conn()
    cu = st.session_state.get("auth_user")
    if not cu:
        st.error("You must be logged in.")
        return
    with st.form("change_pw"):
        p1 = st.text_input("New password", type="password")
        p2 = st.text_input("Confirm new password", type="password")
        go = st.form_submit_button("Change password")
        if go:
            if not p1:
                st.error("Enter a new password.")
            elif p1 != p2:
                st.error("Passwords do not match.")
            else:
                _reset_password(conn, cu, p1)
                st.success("Password changed")

def main():
    conn = _conn()
    _ensure_users_table(conn)

    # First-time setup if there are zero users
    if _count_users(conn) == 0:
        first_time_setup()
        return

    # Sidebar auth panel
    if not st.session_state.get("auth_user"):
        login_panel()
        st.title("Welcome")
        st.info("Please sign in using the sidebar to continue.")
        return

    # Show user badge
    show_user_badge()

    # Admin tools selector
    role = st.session_state.get("auth_role", "viewer")
    if role == "admin":
        tool = st.sidebar.radio("Admin tools", ["Launch App", "User Management", "Change My Password"], index=0)
    else:
        tool = st.sidebar.radio("Account", ["Launch App", "Change My Password"], index=0)

    if tool == "User Management" and role == "admin":
        user_management_panel()
        return
    if tool == "Change My Password":
        change_my_password_panel()
        return

    # Otherwise, launch the main app
    mod = importlib.import_module("rugby_stats_app_v3y")
    if hasattr(mod, "main"):
        # Expose identity to the app
        st.session_state.setdefault("current_user", st.session_state["auth_user"])
        st.session_state.setdefault("current_role", st.session_state["auth_role"])
        mod.main()
    else:
        st.error("Could not find main() in rugby_stats_app_v3y.py")

if __name__ == "__main__":
    main()
