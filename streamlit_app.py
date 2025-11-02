import os, sqlite3, bcrypt
import streamlit as st

def _db_path() -> str:
    # 1) Prefer secret
    try:
        if "RUGBY_DB_PATH" in st.secrets:
            return str(st.secrets["RUGBY_DB_PATH"])
    except Exception:
        pass

    # 2) Prefer env var if set
    if "RUGBY_DB_PATH" in os.environ:
        return os.environ["RUGBY_DB_PATH"]

    # 3) Default — LOCAL storage inside app directory (works on Streamlit Cloud)
    local_dir = ".streamlit_storage"
    os.makedirs(local_dir, exist_ok=True)
    return os.path.join(local_dir, "rugby_stats.db")

DB_PATH = _db_path()

@st.cache_resource
def _conn() -> sqlite3.Connection:
    dp = os.path.dirname(DB_PATH)
    if dp and dp not in ("/", ""):
        try:
            os.makedirs(dp, exist_ok=True)
        except PermissionError:
            # On Streamlit Cloud this is fine; /mount/data usually exists and is writable.
            pass
    c = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    c.row_factory = sqlite3.Row
    # Safer defaults for concurrency
    try:
        c.execute("PRAGMA journal_mode=WAL;")
        c.execute("PRAGMA synchronous=NORMAL;")
    except sqlite3.Error:
        pass
    return c

def _ensure_users_and_migrate(conn: sqlite3.Connection) -> None:
    # 1) Ensure table exists (idempotent)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users(
            username   TEXT PRIMARY KEY,
            pass_hash  BLOB NOT NULL,
            role       TEXT NOT NULL DEFAULT 'admin',
            active     INTEGER NOT NULL DEFAULT 1
        );
    """)

    # 2) If an older schema had a different column name, migrate it safely.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
    # Old builds sometimes had "password_hash" instead of "pass_hash"
    if "password_hash" in cols and "pass_hash" not in cols:
        conn.execute("ALTER TABLE users RENAME TO users_old;")
        conn.execute("""
            CREATE TABLE users(
                username   TEXT PRIMARY KEY,
                pass_hash  BLOB NOT NULL,
                role       TEXT NOT NULL DEFAULT 'admin',
                active     INTEGER NOT NULL DEFAULT 1
            );
        """)
        for row in conn.execute("SELECT username, password_hash FROM users_old;"):
            conn.execute(
                "INSERT OR IGNORE INTO users(username, pass_hash, role, active) VALUES(?,?, 'admin', 1)",
                (row["username"], row["password_hash"]),
            )
        conn.execute("DROP TABLE users_old;")
        cols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}

    # 3) Add any missing columns (idempotent, safe to re-run)
    if "role" not in cols:
        try:
            conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin';")
        except sqlite3.OperationalError:
            pass
    if "active" not in cols:
        try:
            conn.execute("ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1;")
        except sqlite3.OperationalError:
            pass

    conn.commit()

def _ensure_default_admin(conn: sqlite3.Connection) -> None:
    n = conn.execute("SELECT COUNT(*) FROM users;").fetchone()[0]
    if n == 0:
        # Seed default admin only once (empty DB)
        user = os.environ.get("APP_ADMIN_USER", "ACST28")
        pw   = os.environ.get("APP_ADMIN_PASS", "COYB1527")
        ph   = bcrypt.hashpw(pw.encode(), bcrypt.gensalt())
        conn.execute(
            "INSERT INTO users(username, pass_hash, role, active) VALUES(?,?,?,1)",
            (user, ph, "admin"),
        )
        conn.commit()

def _get_user(conn: sqlite3.Connection, username: str):
    r = conn.execute(
        "SELECT username, pass_hash, role, active FROM users WHERE username=?;",
        (username,),
    ).fetchone()
    return (
        {"username": r["username"], "pass_hash": r["pass_hash"], "role": r["role"], "active": int(r["active"])}
        if r else None
    )
