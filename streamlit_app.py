import importlib, os, sqlite3, bcrypt
import streamlit as st

st.set_page_config(page_title="Rugby Stats v5.2 (Roles)", layout="wide")
def _noop(*a, **k): return None
st.set_page_config = _noop

def _db_path():
    try:
        if "RUGBY_DB_PATH" in st.secrets: return str(st.secrets["RUGBY_DB_PATH"])
    except Exception: pass
    return os.environ.get("RUGBY_DB_PATH", os.path.join(".", "rugby_stats.db"))

DB_PATH = _db_path()

@st.cache_resource
def _conn():
    dp = os.path.dirname(DB_PATH)
    if dp and dp not in ("/",""):
        try: os.makedirs(dp, exist_ok=True)
        except PermissionError: pass
    c = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY,
        pass_hash BLOB NOT NULL,
        role TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1
    );"""); c.commit()
    return c

DEFAULT_ADMIN_USERNAME="ACST28"; DEFAULT_ADMIN_PASSWORD="COYB1527"
ROLES = ("admin","editor","viewer")

def _ensure_default_admin():
    c=_conn()
    n=int(c.execute("SELECT COUNT(*) FROM users").fetchone()[0])
    if n==0:
        ph=bcrypt.hashpw(DEFAULT_ADMIN_PASSWORD.encode(), bcrypt.gensalt())
        with c: c.execute("INSERT INTO users(username,pass_hash,role,active) VALUES(?,?,?,1)", (DEFAULT_ADMIN_USERNAME, ph, "admin"))

def _get_user(u):
    r=_conn().execute("SELECT username, pass_hash, role, active FROM users WHERE username=?", (u,)).fetchone()
    return {"username":r[0],"pass_hash":r[1],"role":r[2],"active":int(r[3])} if r else None

def login_panel():
    st.sidebar.header("Login")
    u=st.sidebar.text_input("Username", key="__u")
    p=st.sidebar.text_input("Password", type="password", key="__p")
    if st.sidebar.button("Sign in"):
        rec=_get_user((u or "").strip())
        if rec and rec["active"]==1 and bcrypt.checkpw((p or "").encode(), rec["pass_hash"]):
            st.session_state["auth_user"]=rec["username"]
            st.session_state["auth_role"]=rec["role"]
            st.toast(f"Signed in as {rec['username']} ({rec['role']})", icon="✅")
            st.rerun()
        else:
            st.sidebar.error("Invalid username/password or inactive user")

def admin_users_panel():
    st.title("👤 User Management")
    c=_conn()
    st.subheader("Add User")
    with st.form("add"):
        c1,c2,c3=st.columns([2,2,1])
        with c1: u=st.text_input("Username", placeholder="firstname_surname")
        with c2: p=st.text_input("Password", type="password")
        with c3: r=st.selectbox("Role", ROLES, index=1)
        if st.form_submit_button("Create"):
            if not u or not p: st.error("Username and password required")
            elif _get_user(u): st.error("User already exists")
            else:
                ph=bcrypt.hashpw(p.encode(), bcrypt.gensalt())
                with c: c.execute("INSERT INTO users(username,pass_hash,role,active) VALUES(?,?,?,1)", (u,ph,r))
                st.success("User created"); st.rerun()
    st.subheader("Existing Users")
    for u, role, active in c.execute("SELECT username, role, active FROM users ORDER BY username"):
        with st.expander(f"{u} — {role} — {'Active' if active else 'Inactive'}", expanded=False):
            col1,col2,col3,col4=st.columns(4)
            with col1:
                nr=st.selectbox("Role", ROLES, index=ROLES.index(role), key=f"r_{u}")
                if st.button("Update role", key=f"rb_{u}"):
                    with c: c.execute("UPDATE users SET role=? WHERE username=?", (nr,u))
                    st.success("Updated"); st.rerun()
            with col2:
                act=st.toggle("Active", value=bool(active), key=f"a_{u}")
                if st.button("Apply", key=f"ab_{u}"):
                    with c: c.execute("UPDATE users SET active=? WHERE username=?", (int(act),u))
                    st.success("Updated"); st.rerun()
            with col3:
                np=st.text_input("New password", type="password", key=f"p_{u}")
                if st.button("Reset password", key=f"pb_{u}"):
                    if not np: st.error("Enter a password first")
                    else:
                        ph=bcrypt.hashpw(np.encode(), bcrypt.gensalt())
                        with c: c.execute("UPDATE users SET pass_hash=? WHERE username=?", (ph,u))
                        st.success("Password updated")
            with col4:
                if st.button("Delete user", key=f"d_{u}"):
                    if u==st.session_state.get("auth_user"): st.error("Cannot delete your own account")
                    else:
                        with c: c.execute("DELETE FROM users WHERE username=?", (u,))
                        st.warning("Deleted"); st.rerun()

def main():
    _ensure_default_admin()
    st.sidebar.caption(f"DB: {DB_PATH}")
    if not st.session_state.get("auth_user"):
        login_panel()
        st.title("Welcome"); st.info("Please sign in using the left sidebar."); return
    # header with logout
    cols=st.columns([1,1,1,1,1,1,1,1])
    with cols[-1]:
        if st.button("Logout"):
            for k in ("auth_user","auth_role"): st.session_state.pop(k, None); st.rerun()
    # admin tools toggle
    if st.session_state.get("auth_role")=="admin":
        tool=st.sidebar.radio("Admin tools", ["Launch App","User Management"], index=0)
        if tool=="User Management":
            admin_users_panel(); return
    # pass role to app
    st.session_state.setdefault("current_user", st.session_state.get("auth_user"))
    st.session_state.setdefault("current_role", st.session_state.get("auth_role","viewer"))
    mod=importlib.import_module("rugby_stats_app_roles_main")
    mod.main()

if __name__ == "__main__": main()
