import importlib, os, sqlite3, bcrypt
import streamlit as st

st.set_page_config(page_title="Match Stat Collector v5", layout="wide")
def _noop(*a, **k): return None
# Prevent “set_page_config called twice” if imported twice
st.set_page_config = _noop

def _db_path():
    try:
        if "RUGBY_DB_PATH" in st.secrets:
            return str(st.secrets["RUGBY_DB_PATH"])
    except Exception:
        pass
    return os.environ.get("RUGBY_DB_PATH", "/mount/data/rugby_stats.db")

DB_PATH = _db_path()

@st.cache_resource
def _conn():
    dp = os.path.dirname(DB_PATH)
    if dp and dp not in ("/",""):
        try:
            os.makedirs(dp, exist_ok=True)
        except PermissionError:
            pass
    c = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    c.row_factory = sqlite3.Row
    return c

def _ensure_users_and_migrate(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users(
            username TEXT PRIMARY KEY,
            pass_hash BLOB NOT NULL,
            role TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
        );
    """)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "password_hash" in cols and "pass_hash" not in cols:
        # migrate old column name
        conn.execute("ALTER TABLE users RENAME TO users_old")
        conn.execute("""
            CREATE TABLE users(
                username TEXT PRIMARY KEY,
                pass_hash BLOB NOT NULL,
                role TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1
            );
        """)
        for row in conn.execute("SELECT username,password_hash FROM users_old"):
            conn.execute(
                "INSERT OR IGNORE INTO users(username,pass_hash,role,active) VALUES(?,?, 'admin',1)",
                (row["username"], row["password_hash"])
            )
        conn.execute("DROP TABLE users_old")
    cols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "role" not in cols:   conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'")
    if "active" not in cols: conn.execute("ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1")
    conn.commit()

def _ensure_default_admin(conn):
    n = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if n == 0:
        user = os.environ.get("APP_ADMIN_USER","ACST28")
        pw   = os.environ.get("APP_ADMIN_PASS","COYB1527")
        ph   = bcrypt.hashpw(pw.encode(), bcrypt.gensalt())
        with conn:
            conn.execute("INSERT INTO users(username,pass_hash,role,active) VALUES(?,?,?,1)", (user,ph,"admin"))

def _get_user(conn, username):
    r = conn.execute("SELECT username,pass_hash,role,active FROM users WHERE username=?", (username,)).fetchone()
    return {"username":r["username"],"pass_hash":r["pass_hash"],"role":r["role"],"active":int(r["active"])} if r else None

def _login_panel(conn):
    st.sidebar.header("Login")
    u = st.sidebar.text_input("Username")
    p = st.sidebar.text_input("Password", type="password")
    if st.sidebar.button("Sign in"):
        rec = _get_user(conn, (u or "").strip())
        if rec and rec["active"]==1 and bcrypt.checkpw((p or "").encode(), rec["pass_hash"]):
            st.session_state["auth_user"] = rec["username"]
            st.session_state["auth_role"] = rec["role"]
            st.rerun()
        else:
            st.sidebar.error("Invalid username/password or inactive user")

def _user_mgmt_panel(conn):
    st.title("👤 User Management (Admin)")
    st.subheader("Add User")
    with st.form("add_user"):
        c1,c2,c3 = st.columns([2,2,1])
        with c1: nu = st.text_input("Username", placeholder="firstname_surname")
        with c2: np = st.text_input("Password", type="password")
        with c3: nr = st.selectbox("Role", ["admin","editor","viewer"], index=1)
        if st.form_submit_button("Create"):
            if not nu or not np:
                st.error("Username and password required")
            elif _get_user(conn, nu):
                st.error("User already exists")
            else:
                ph = bcrypt.hashpw(np.encode(), bcrypt.gensalt())
                with conn:
                    conn.execute("INSERT INTO users(username,pass_hash,role,active) VALUES(?,?,?,1)", (nu,ph,nr))
                st.success("User created")
                st.rerun()
    st.subheader("Existing Users")
    rows = conn.execute("SELECT username,role,active FROM users ORDER BY username").fetchall()
    for r in rows:
        u, role, active = r["username"], r["role"], int(r["active"])
        with st.expander(f"{u} — {role} — {'Active' if active else 'Inactive'}", expanded=False):
            col1,col2,col3,col4 = st.columns(4)
            with col1:
                nr = st.selectbox("Role", ["admin","editor","viewer"], index=["admin","editor","viewer"].index(role), key=f"role_{u}")
                if st.button("Update Role", key=f"rbtn_{u}"):
                    with conn: conn.execute("UPDATE users SET role=? WHERE username=?", (nr,u))
                    st.success("Updated"); st.rerun()
            with col2:
                act = st.toggle("Active", value=bool(active), key=f"act_{u}")
                if st.button("Apply Active", key=f"abtn_{u}"):
                    with conn: conn.execute("UPDATE users SET active=? WHERE username=?", (int(act),u))
                    st.success("Updated"); st.rerun()
            with col3:
                npw = st.text_input("New password", type="password", key=f"pwd_{u}")
                if st.button("Reset Password", key=f"pbtn_{u}"):
                    if not npw: st.error("Enter a new password first")
                    else:
                        ph = bcrypt.hashpw(npw.encode(), bcrypt.gensalt())
                        with conn: conn.execute("UPDATE users SET pass_hash=? WHERE username=?", (ph,u))
                        st.success("Password reset")
            with col4:
                if st.button("Delete User", key=f"dbtn_{u}"):
                    if u==st.session_state.get("auth_user"):
                        st.error("Cannot delete your own account")
                    else:
                        with conn: conn.execute("DELETE FROM users WHERE username=?", (u,))
                        st.warning("User deleted"); st.rerun()

def main():
    conn = _conn(); _ensure_users_and_migrate(conn); _ensure_default_admin(conn)

    st.sidebar.caption(f"DB: {DB_PATH}")
    if not st.session_state.get("auth_user"):
        _login_panel(conn)
        st.title("Welcome"); st.info("Please sign in using the sidebar."); return

    cols = st.columns([1,1,1,1,1,1,1,1])
    with cols[-1]:
        if st.button("Logout"):
            for k in ("auth_user","auth_role"): st.session_state.pop(k, None)
            st.rerun()

    role = st.session_state.get("auth_role","viewer")
    if role=="admin":
        tool = st.sidebar.radio("Admin Tools", ["Launch App","User Management"], index=0)
        if tool=="User Management": _user_mgmt_panel(conn); return

    st.session_state.setdefault("current_user", st.session_state.get("auth_user"))
    st.session_state.setdefault("current_role", role)

    mod = importlib.import_module("rugby_stats_app_v5_main")
    mod.main()

if __name__=="__main__":
    main()
