#!/usr/bin/env python3
import os, sqlite3, datetime as dt
from typing import Dict, Optional, List
import pandas as pd
import streamlit as st
import traceback

import base64, io

def get_setting(conn, key, default=None):
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default

def set_setting(conn, key, value):
    with conn:
        conn.execute("INSERT OR REPLACE INTO settings(key, value) VALUES(?,?)", (key, value))


# ------------------------ Auth / Roles ------------------------ #
def _hash_pw_bcrypt(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def _check_pw_bcrypt(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

def ensure_admin_user(conn):
    # Create default admin if no users
    count = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
    if count == 0:
        with conn:
            conn.execute("INSERT INTO users(username, password_hash, role, active) VALUES(?,?,?,1)",
                         ("admin", _hash_pw_bcrypt("changeme"), "Admin"))
        return True
    return False

def login_widget(conn):
    st.session_state.setdefault("user", None)
    if st.session_state["user"]:
        return st.session_state["user"]
    st.sidebar.subheader("Sign in")
    u = st.sidebar.text_input("Username")
    p = st.sidebar.text_input("Password", type="password")
    if st.sidebar.button("Login"):
        row = conn.execute("SELECT id, username, role, active, password_hash FROM users WHERE username=?", (u.strip(),)).fetchone()
        if row and row["active"]==1 and _check_pw_bcrypt(p, row["password_hash"]):
            st.session_state["user"] = {"id": row["id"], "username": row["username"], "role": row["role"]}
            st.sidebar.success(f"Welcome, {row['username']}"); st.rerun()
        else:
            st.sidebar.error("Invalid credentials")
    return None

def logout_button():
    if st.sidebar.button("Logout"):
        st.session_state.pop("user", None)
        st.rerun()

def has_role(user, roles):
    if not user: return False
    if isinstance(roles, str): roles = [roles]
    return user.get("role") in roles
def ensure_admin_user(conn):
    # Create default admin if no users
    count = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
    if count == 0:
        with conn:
            conn.execute("INSERT INTO users(username, password_hash, role, active) VALUES(?,?,?,1)",
                         ("admin", _hash_pw_bcrypt("changeme"), "Admin"))
        return True
    return False

def login_widget(conn):
    st.session_state.setdefault("user", None)
    if st.session_state["user"]:
        return st.session_state["user"]
    st.sidebar.subheader("Sign in")
    u = st.sidebar.text_input("Username")
    p = st.sidebar.text_input("Password", type="password")
    if st.sidebar.button("Login"):
        salt = _get_salt(conn)
        row = conn.execute("SELECT id, username, role, active, password_hash FROM users WHERE username=?", (u.strip(),)).fetchone()
        if row and row["active"]==1 and row["password_hash"] == _hash_pw(p, salt):
            st.session_state["user"] = {"id": row["id"], "username": row["username"], "role": row["role"]}
            st.sidebar.success(f"Welcome, {row['username']}"); st.rerun()
        else:
            st.sidebar.error("Invalid credentials")
    return None

def logout_button():
    if st.sidebar.button("Logout"):
        st.session_state.pop("user", None)
        st.rerun()

def has_role(user, roles):
    if not user: return False
    if isinstance(roles, str): roles = [roles]
    return user.get("role") in roles






# ------------------------ Audit logging ------------------------ #
def _user_ctx():
    u = st.session_state.get("user")
    if not u: return ("anonymous", "unknown")
    return (u.get("username","anonymous"), u.get("role","unknown"))

def log_action(conn, action: str, details: dict):
    try:
        username, role = _user_ctx()
        with conn:
            conn.execute(
                "INSERT INTO audit_log(ts, username, role, action, details) VALUES(?,?,?,?,?)",
                (dt.datetime.now().isoformat(timespec="seconds"), username, role, action, json.dumps(details, ensure_ascii=False))
            )
    except Exception:
        pass


def get_pinger_token(conn):
    tok = get_setting(conn, "backup.pinger_token", "")
    if not tok:
        tok = base64.urlsafe_b64encode(secrets.token_bytes(12)).decode("utf-8").rstrip("=")
        set_setting(conn, "backup.pinger_token", tok)
    return tok

def rotate_pinger_token(conn):
    tok = base64.urlsafe_b64encode(secrets.token_bytes(12)).decode("utf-8").rstrip("=")
    set_setting(conn, "backup.pinger_token", tok)
    return tok


def get_backup_status(conn):
    last_ok = get_setting(conn, "backup.last_ok", "")
    last_try = get_setting(conn, "backup.last_try", "")
    sched_time = get_setting(conn, "backup.schedule_time", "02:30")
    sched_on = get_setting(conn, "backup.schedule_enabled", "0") == "1"
    return last_ok, last_try, sched_time, sched_on

def set_backup_status(conn, *, ok: str=None, tried: str=None):
    if ok is not None:
        set_setting(conn, "backup.last_ok", ok)
    if tried is not None:
        set_setting(conn, "backup.last_try", tried)

def set_backup_schedule(conn, *, enabled: bool, time_str: str):
    set_setting(conn, "backup.schedule_enabled", "1" if enabled else "0")
    # validate HH:MM
    try:
        dt.datetime.strptime(time_str, "%H:%M")
    except Exception:
        time_str = "02:30"
    set_setting(conn, "backup.schedule_time", time_str)


def _is_match_locked(conn, match_id:int) -> bool:
    try:
        row = conn.execute("SELECT locked FROM matches WHERE id=?", (int(match_id),)).fetchone()
        return bool(row and row["locked"]==1)
    except Exception:
        return False


def _now_iso():
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def run_nightly_backup_if_due(conn):
    # Runs at-most once per calendar day after the scheduled time, when app is accessed
    _, _, sched_time, sched_on = get_backup_status(conn)
    if not sched_on:
        return
    # parse scheduled time today
    try:
        hh, mm = [int(x) for x in sched_time.split(":")]
    except Exception:
        hh, mm = 2, 30
    now = dt.datetime.now()
    due_today = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    last_ok = get_setting(conn, "backup.last_ok", "") or ""
    last_ok_date = last_ok.split(" ")[0] if last_ok else ""
    today_str = now.strftime("%Y-%m-%d")
    if now >= due_today and last_ok_date != today_str:
        set_backup_status(conn, tried=_now_iso())
        ok = backup_db_to_dropbox(conn, label="nightly")
        if ok:
            set_backup_status(conn, ok=_now_iso())


def get_dropbox_settings(conn):
    token = get_setting(conn, "backup.dropbox.token", "")
    folder = get_setting(conn, "backup.dropbox.folder", "/Apps/RugbyStats/backups")
    auto = get_setting(conn, "backup.dropbox.auto", "0")
    return token, folder, auto == "1"

def set_dropbox_settings(conn, token:str, folder:str, auto:bool):
    set_setting(conn, "backup.dropbox.token", token.strip())
    set_setting(conn, "backup.dropbox.folder", folder.strip() or "/Apps/RugbyStats/backups")
    set_setting(conn, "backup.dropbox.auto", "1" if auto else "0")

def _dropbox_backup_enabled(conn):
    token, folder, auto = get_dropbox_settings(conn); return bool(token.strip())

def backup_db_to_dropbox(conn, *, label: str = "") -> bool:
    try:
        token, folder, _ = get_dropbox_settings(conn)
        if not token.strip():
            return False
        # Lazy import to avoid breaking if package missing at runtime
        import dropbox  # type: ignore
        db_path = DB_FILE
        with open(db_path, "rb") as f:
            data = f.read()
        set_backup_status(conn, tried=_now_iso())
        ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = os.path.basename(db_path)
        versioned = f"{folder.rstrip('/')}/{base_name.rsplit('.',1)[0]}_{ts}.db"
        latest = f"{folder.rstrip('/')}/{base_name}"
        dbx = dropbox.Dropbox(token)
        dbx.files_upload(data, versioned, mode=dropbox.files.WriteMode("overwrite"))
        dbx.files_upload(data, latest, mode=dropbox.files.WriteMode("overwrite"))
        set_backup_status(conn, ok=_now_iso())
        return True
    except Exception as e:
        st.warning(f"Dropbox backup failed: {e}")
        st.caption(traceback.format_exc())
        return False

def maybe_auto_backup(conn, *, label: str = ""):
    try:
        token, folder, auto = get_dropbox_settings(conn)
        if auto:
            backup_db_to_dropbox(conn, label=label)
    except Exception:
        pass



# ------------------------ Dependency checks & installer ------------------------ #
import importlib, sys, subprocess

REQUIRED_PACKAGES = {
    "xlsxwriter": "xlsxwriter>=3.2",
    "dropbox": "dropbox>=12.0",
    "bcrypt": "bcrypt>=4.2"
}

def _is_installed(modname: str) -> bool:
    try:
        importlib.import_module(modname)
        return True
    except Exception:
        return False

def _pip_install(spec: str) -> bool:
    try:
        st.info(f"Installing {spec}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", spec])
        st.success(f"Installed {spec}")
        return True
    except Exception as e:
        st.error(f"Install failed for {spec}: {e}")
        return False

def deps_status():
    return {k: _is_installed(k) for k in REQUIRED_PACKAGES.keys()}



# ------------------------ Custom Metrics ------------------------ #
import json as _json

def get_custom_metrics(conn):
    raw = get_setting(conn, "metrics.custom", "[]")
    try:
        arr = _json.loads(raw)
        out = []
        for m in arr:
            if isinstance(m, dict) and "code" in m and "label" in m:
                out.append({
                    "code": m["code"].strip(),
                    "label": m["label"].strip(),
                    "group": m.get("group","Custom"),
                    "show_logger": bool(m.get("show_logger", True)),
                    "show_reports": bool(m.get("show_reports", True)),
                })
        return out
    except Exception:
        return []

def set_custom_metrics(conn, metrics_list):
    try:
        set_setting(conn, "metrics.custom", _json.dumps(metrics_list, ensure_ascii=False))
        return True
    except Exception:
        return False

def get_branding(conn):
    logo_b64 = get_setting(conn, "branding.logo_b64", None)
    primary = get_setting(conn, "branding.primary", "#2563eb")
    return logo_b64, primary


DB_FILE = os.environ.get("RUGBY_DB", "rugby_stats.db")

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS players (id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,position TEXT,notes TEXT,active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS matches (id INTEGER PRIMARY KEY AUTOINCREMENT,date TEXT NOT NULL,opponent TEXT NOT NULL,competition TEXT,location TEXT,team_score INTEGER,opp_score INTEGER);

CREATE TABLE IF NOT EXISTS player_match_metric_totals (
  match_id INTEGER NOT NULL,
  player_id INTEGER NOT NULL,
  metric_code TEXT NOT NULL,
  total INTEGER NOT NULL DEFAULT 0,
  UNIQUE(match_id, player_id, metric_code),
  FOREIGN KEY (match_id) REFERENCES matches(id) ON DELETE CASCADE,
  FOREIGN KEY (player_id) REFERENCES players(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS player_match_stats (id INTEGER PRIMARY KEY AUTOINCREMENT,match_id INTEGER NOT NULL,player_id INTEGER NOT NULL,minutes INTEGER DEFAULT 0,starts INTEGER DEFAULT 0,tries INTEGER DEFAULT 0,conversions INTEGER DEFAULT 0,penalties INTEGER DEFAULT 0,drop_goals INTEGER DEFAULT 0,carries_made INTEGER DEFAULT 0,tackles_made INTEGER DEFAULT 0,tackles_missed INTEGER DEFAULT 0,turnovers_won INTEGER DEFAULT 0,turnovers_conceded INTEGER DEFAULT 0,line_breaks INTEGER DEFAULT 0,offloads INTEGER DEFAULT 0,handling_errors INTEGER DEFAULT 0,kick_gain INTEGER DEFAULT 0,kick_no_gain INTEGER DEFAULT 0,assists INTEGER DEFAULT 0,penalties_conceded INTEGER DEFAULT 0,UNIQUE(match_id, player_id),FOREIGN KEY (match_id) REFERENCES matches(id) ON DELETE CASCADE,FOREIGN KEY (player_id) REFERENCES players(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS match_squad (match_id INTEGER NOT NULL,player_id INTEGER NOT NULL,shirt_number INTEGER NOT NULL,starting INTEGER NOT NULL DEFAULT 1,PRIMARY KEY (match_id, player_id),UNIQUE (match_id, shirt_number),FOREIGN KEY (match_id) REFERENCES matches(id) ON DELETE CASCADE,FOREIGN KEY (player_id) REFERENCES players(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT,ts TEXT NOT NULL,match_id INTEGER NOT NULL,player_id INTEGER NOT NULL,event TEXT NOT NULL,value INTEGER NOT NULL DEFAULT 1,note TEXT,FOREIGN KEY (match_id) REFERENCES matches(id) ON DELETE CASCADE,FOREIGN KEY (player_id) REFERENCES players(id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS idx_events_match ON events(match_id);
CREATE INDEX IF NOT EXISTS idx_events_player ON events(player_id);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY,value TEXT NOT NULL);

-- Users & roles
CREATE TABLE IF NOT EXISTS users (

  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('Admin', 'Coach', 'Analyst', 'Viewer')),
  active INTEGER NOT NULL DEFAULT 1
);
"""
DEFAULT_POINTS = {"try":5,"conversion":2,"penalty":3,"drop_goal":3}
EVENTS_CATALOG: List[str] = ["try","conversion","penalty","drop_goal","carry_made","tackle_made","tackle_missed","turnover_won","turnover_conceded","line_break","offload","handling_error","kick_gain","kick_no_gain","assist"]

@st.cache_resource(show_spinner=False)
def get_conn()->sqlite3.Connection:
    conn=sqlite3.connect(DB_FILE,check_same_thread=False); conn.row_factory=sqlite3.Row
    with conn: conn.executescript(SCHEMA); _migrate_existing(conn)
    if not conn.execute("SELECT 1 FROM settings WHERE key LIKE 'points.%' LIMIT 1").fetchone():
        for k,v in DEFAULT_POINTS.items(): conn.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)",(f"points.{k}",str(v)))
    return conn

def _migrate_existing(conn):
    cols={r["name"] for r in conn.execute("PRAGMA table_info(player_match_stats)").fetchall()}
    needed={"carries_made":"INTEGER DEFAULT 0","tackles_made":"INTEGER DEFAULT 0","tackles_missed":"INTEGER DEFAULT 0","turnovers_won":"INTEGER DEFAULT 0","turnovers_conceded":"INTEGER DEFAULT 0","line_breaks":"INTEGER DEFAULT 0","offloads":"INTEGER DEFAULT 0","handling_errors":"INTEGER DEFAULT 0","kick_gain":"INTEGER DEFAULT 0","kick_no_gain":"INTEGER DEFAULT 0", "penalties_conceded":"INTEGER DEFAULT 0"}
    for k,decl in needed.items():
        if k not in cols: conn.execute(f"ALTER TABLE player_match_stats ADD COLUMN {k} {decl}")

def get_points(conn): 
    rows=conn.execute("SELECT key,value FROM settings WHERE key LIKE 'points.%'").fetchall(); pts=DEFAULT_POINTS.copy()
    for r in rows: pts[r["key"].split(".",1)[1]]=int(r["value"]); return pts

def df_players(conn): return pd.read_sql_query("SELECT id,name,position,notes,active FROM players ORDER BY name",conn)
def df_matches(conn): return pd.read_sql_query("SELECT id,date,opponent,competition,location,team_score,opp_score FROM matches ORDER BY date DESC",conn)
def df_match_squad(conn,mid:int): 
    return pd.read_sql_query("SELECT ms.match_id,ms.player_id,ms.shirt_number,ms.starting,p.name,p.position FROM match_squad ms JOIN players p ON p.id=ms.player_id WHERE ms.match_id=? ORDER BY ms.shirt_number",conn,params=(mid,))
def df_events(conn,mid:Optional[int]=None):
    if mid: return pd.read_sql_query("SELECT * FROM events WHERE match_id=? ORDER BY ts DESC",conn,params=(mid,))
    return pd.read_sql_query("SELECT * FROM events ORDER BY ts DESC",conn)

def aggregate_events_to_stats(conn,mid:int):
    map_counts={"try":"tries","conversion":"conversions","penalty":"penalties","drop_goal":"drop_goals","carry_made":"carries_made","tackle_made":"tackles_made","tackle_missed":"tackles_missed","turnover_won":"turnovers_won","turnover_conceded":"turnovers_conceded","line_break":"line_breaks","offload":"offloads","handling_error":"handling_errors","kick_gain":"kick_gain","kick_no_gain":"kick_no_gain","assist":"assists"}
    rows=conn.execute("SELECT player_id,event,SUM(value) as total FROM events WHERE match_id=? GROUP BY player_id,event",(mid,)).fetchall(); per={}
    for r in rows:
        pid,evt,val=r["player_id"],r["event"],int(r["total"] or 0)
        if evt not in map_counts: continue
        agg=per.setdefault(pid,{k:0 for k in ["minutes","starts","tries","conversions","penalties","drop_goals","carries_made","tackles_made","tackles_missed","turnovers_won","turnovers_conceded","line_breaks","offloads","handling_errors","kick_gain","kick_no_gain","assists"]})
        agg[map_counts[evt]]+=val
    with conn:
        for pid,a in per.items():
            conn.execute("""INSERT INTO player_match_stats(match_id,player_id,minutes,starts,tries,conversions,penalties,drop_goals,carries_made,tackles_made,tackles_missed,turnovers_won,turnovers_conceded,line_breaks,offloads,handling_errors,kick_gain,kick_no_gain,assists) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(match_id,player_id) DO UPDATE SET tries=excluded.tries,conversions=excluded.conversions,penalties=excluded.penalties,drop_goals=excluded.drop_goals,carries_made=excluded.carries_made,tackles_made=excluded.tackles_made,tackles_missed=excluded.tackles_missed,turnovers_won=excluded.turnovers_won,turnovers_conceded=excluded.turnovers_conceded,line_breaks=excluded.line_breaks,offloads=excluded.offloads,handling_errors=excluded.handling_errors,kick_gain=excluded.kick_gain,kick_no_gain=excluded.kick_no_gain,assists=excluded.assists""",(mid,pid,a.get("minutes",0),a.get("starts",0),a.get("tries",0),a.get("conversions",0),a.get("penalties",0),a.get("drop_goals",0),a.get("carries_made",0),a.get("tackles_made",0),a.get("tackles_missed",0),a.get("turnovers_won",0),a.get("turnovers_conceded",0),a.get("line_breaks",0),a.get("offloads",0),a.get("handling_errors",0),a.get("kick_gain",0),a.get("kick_no_gain",0),a.get("assists",0)))

    # Populate generic metric totals table for this match
    df = pd.read_sql_query(
        "SELECT player_id, event as metric_code, SUM(value) as total FROM events WHERE match_id=? GROUP BY player_id, event",
        conn, params=(int(mid),)
    )
    with conn:
        conn.execute("DELETE FROM player_match_metric_totals WHERE match_id=?", (int(mid),))
        for _, r in df.iterrows():
            conn.execute(
                "INSERT INTO player_match_metric_totals(match_id, player_id, metric_code, total) VALUES(?,?,?,?)",
                (int(mid), int(r["player_id"]), str(r["metric_code"]), int(r["total"] or 0))
            )


def page_players(conn):
    st.header("Players")

    with st.expander("Add Player", expanded=False):
        with st.form("add_player_form"):
            name = st.text_input("Name")
            position = st.text_input("Position")
            notes = st.text_area("Notes")
            if st.form_submit_button("Add Player") and name.strip():
                with conn:
                    conn.execute("INSERT INTO players(name, position, notes, active) VALUES(?,?,?,1)", (name.strip(), position.strip() or None, notes.strip() or None))
                st.success(f"Added player {name}")
                log_action(conn,"player_add",{"name":name,"position":position})
                maybe_auto_backup(conn, label="add_player")

    with st.expander("Edit / Remove Player", expanded=True):
        if not has_role(st.session_state.get("user"), ["Coach","Admin"]):
            st.info("Only Coaches and Admins can edit players.");
            st.stop()
        players_df = df_players(conn)
        if players_df.empty:
            st.info("No players yet.")
        else:
            pid = st.selectbox(
                "Select player",
                players_df["id"].astype(int).tolist(),
                format_func=lambda x: (lambda r: f"{r['name']} — {r['position'] or '-'} (#{r['id']})")(players_df[players_df['id']==x].iloc[0])
            )
            row = players_df[players_df["id"]==pid].iloc[0]
            with st.form("edit_form"):
                new_name = st.text_input("Name", value=row["name"] or "")
                new_pos = st.text_input("Position", value=row["position"] or "")
                new_notes = st.text_area("Notes", value=row["notes"] or "")
                new_active = st.checkbox("Active", value=bool(row["active"]))
                c1, c2, c3 = st.columns(3)
                with c1:
                    save = st.form_submit_button("Save changes")
                with c2:
                    deactivate = st.form_submit_button("Deactivate")
                with c3:
                    delete = st.form_submit_button("Delete permanently")

            if save:
                with conn:
                    conn.execute("UPDATE players SET name=?, position=?, notes=?, active=? WHERE id=?", (new_name.strip(), new_pos.strip() or None, new_notes.strip() or None, 1 if new_active else 0, int(pid)))
                st.success("Saved")
                log_action(conn,"player_edit",{"player_id":int(pid),"name":new_name,"position":new_pos,"active":int(new_active)})
                maybe_auto_backup(conn, label="edit_player")
                st.rerun()
            if deactivate:
                with conn:
                    conn.execute("UPDATE players SET active=0 WHERE id=?", (int(pid),))
                st.success("Player deactivated")
                log_action(conn,"player_deactivate",{"player_id":int(pid)})
                maybe_auto_backup(conn, label="deactivate_player")
                st.rerun()
            if delete:
                user = st.session_state.get("user", {})
                if not has_role(user, "Admin"):
                    st.error("Only Admins can delete permanently.")
                else:
                    confirm = st.text_input("Type the player's name to confirm permanent delete:")
                    if st.button("Confirm permanent delete"):
                        if confirm.strip() == row["name"]:
                            with conn:
                                conn.execute("DELETE FROM players WHERE id=?", (int(pid),))
                            st.success("Player deleted"); log_action(conn,"player_delete",{"player_id":int(pid)}); maybe_auto_backup(conn, label="delete_player"); st.rerun()
                        else:
                            st.error("Name did not match. Delete cancelled.")

    st.dataframe(df_players(conn), use_container_width=True, hide_index=True)

def page_matches(conn):
    st.header("Matches")
    with st.expander("Add Match",expanded=True):
        with st.form("add_match_form"):
            date=st.date_input("Date",value=dt.date.today()); opponent=st.text_input("Opponent"); competition=st.text_input("Competition"); location=st.selectbox("Location",["Home","Away","Neutral","Other"],index=0)
            team_score=st.number_input("Team Score",min_value=0,step=1); opp_score=st.number_input("Opponent Score",min_value=0,step=1)
            if st.form_submit_button("Add Match") and opponent.strip():
                with conn: conn.execute("INSERT INTO matches(date,opponent,competition,location,team_score,opp_score) VALUES(?,?,?,?,?,?)",(date.isoformat(),opponent.strip(),competition.strip() or None,location,int(team_score),int(opp_score))); st.success("Match added")
                log_action(conn,"match_add",{"opponent":opponent,"date":date})
                maybe_auto_backup(conn, label="add_match")
    st.dataframe(df_matches(conn),use_container_width=True,hide_index=True)

    st.markdown("#### Lock / Unlock Match")
    mdf = df_matches(conn)
    if not mdf.empty:
        mopt = st.selectbox("Select match", mdf["id"].astype(int).tolist(), format_func=lambda x: (lambda r: f"{r['date']} vs {r['opponent']} (Locked: {r.get('locked',0)})")(mdf[mdf['id']==x].iloc[0]))
        lock_state = int(mdf[mdf["id"]==mopt]["locked"].iloc[0]) if "locked" in mdf.columns else 0
        colL, colU = st.columns(2)
        with colL:
            if st.button("Lock match (make read-only)") and lock_state==0:
                with conn: conn.execute("UPDATE matches SET locked=1 WHERE id=?", (int(mopt),))
                st.success("Match locked"); log_action(conn,"match_lock",{"match_id":int(mopt)}); st.rerun()
        with colU:
            if st.button("Unlock match") and lock_state==1 and has_role(st.session_state.get("user"), ["Coach","Admin"]):
                with conn: conn.execute("UPDATE matches SET locked=0 WHERE id=?", (int(mopt),))
                st.success("Match unlocked"); log_action(conn,"match_unlock",{"match_id":int(mopt)}); st.rerun()
    
def page_squad(conn):
    st.header("Match Squad (Per‑Match Numbers)")
    matches = df_matches(conn)
    if matches.empty:
        st.info("Add a match first on the Matches page."); return
    mid = st.selectbox(
        "Match",
        matches["id"].astype(int).tolist(),
        format_func=lambda x: f"#{x} — {matches[matches['id']==x]['date'].iloc[0]} vs {matches[matches['id']==x]['opponent'].iloc[0]}",
    )
    active_players = pd.read_sql_query("SELECT id, name, position FROM players WHERE active=1 ORDER BY name", conn)
    current = df_match_squad(conn, int(mid))

    base = active_players.merge(current[["player_id","shirt_number","starting"]], left_on="id", right_on="player_id", how="left")
    if "player_id" in base.columns:
        base = base.drop(columns=["player_id"])
    base = base.rename(columns={"id":"player_id"})

    base["shirt_number"] = base["shirt_number"].fillna(0).astype(int)
    base["starting"] = base["starting"].fillna(0).astype(int)

    edited = st.data_editor(
        base[["player_id","name","position","shirt_number","starting"]],
        column_config={
            "player_id": st.column_config.NumberColumn(disabled=True),
            "shirt_number": st.column_config.NumberColumn(min_value=0, max_value=30, step=1, help="0 = not selected"),
            "starting": st.column_config.CheckboxColumn(help="Tick if starting"),
        },
        num_rows="fixed",
        use_container_width=True,
    )

    c1, c2, c3 = st.columns(3)
    with c1:
        if st.button("Clear numbers"):
            edited.loc[:, "shirt_number"] = 0
            st.session_state["_edited_squad"] = edited
            st.rerun()
    with c2:
        if st.button("Validate"):
            starters_df = edited[edited["starting"] == 1].copy()
            starter_nums = starters_df["shirt_number"][starters_df["shirt_number"] > 0]
            dups_all = edited["shirt_number"][edited["shirt_number"] > 0]
            dup_vals = sorted(set(dups_all[dups_all.duplicated()].tolist()))

            starters_count = int((edited["starting"] == 1).sum())
            missing_starter_numbers = int((starters_df["shirt_number"] == 0).sum())
            out_of_range_starters = starters_df[(starters_df["shirt_number"] < 1) | (starters_df["shirt_number"] > 23)]["shirt_number"].tolist()
            starters_not_in_1_15 = starters_df[(starters_df["shirt_number"] < 1) | (starters_df["shirt_number"] > 15)]["shirt_number"].tolist()

            if dup_vals:
                st.error(f"Duplicate shirt numbers found: {dup_vals}")
            else:
                st.success("✅ No duplicate numbers.")

            if starters_count != 15:
                st.warning(f"Starters selected: {starters_count}. (Tip: usually 15)")
            else:
                st.info("Starters selected: 15.")

            if missing_starter_numbers > 0:
                st.error(f"{missing_starter_numbers} starter(s) have no shirt number assigned.")
            else:
                st.success("✅ All starters have numbers.")

            if out_of_range_starters:
                st.warning(f"Some starters have numbers outside 1–23: {sorted(set(out_of_range_starters))}")
            if starters_not_in_1_15:
                st.caption("Tip: Starter numbers are typically 1–15.")

    with c3:
        if _is_match_locked(conn, int(mid)):
            st.error("This match is locked (read-only). Unlock it on the Matches page to edit the squad.")
        elif st.button("Save Squad"):
            nums = edited["shirt_number"][edited["shirt_number"] > 0]
            if nums.duplicated().any():
                st.error("Duplicate shirt numbers found. Each number must be unique.")
            else:
                with conn:
                    conn.execute("DELETE FROM match_squad WHERE match_id=?", (int(mid),))
                    for _, row in edited.iterrows():
                        if int(row["shirt_number"]) > 0:
                            conn.execute(
                                "INSERT INTO match_squad(match_id, player_id, shirt_number, starting) VALUES(?,?,?,?)",
                                (int(mid), int(row["player_id"]), int(row["shirt_number"]), int(row["starting"]))
                            )
                st.success("Squad saved")

                log_action(conn,"squad_save",{"match_id":int(mid)})

                maybe_auto_backup(conn, label="save_squad")

                # Auto-populate starts in player_match_stats based on squad

                cur = conn.execute("SELECT player_id, starting FROM match_squad WHERE match_id=?", (int(mid),))

                for pid_row, start_flag in cur.fetchall():

                    conn.execute(

                        "INSERT INTO player_match_stats(match_id, player_id, minutes, starts) VALUES(?,?,?,?) "

                        "ON CONFLICT(match_id, player_id) DO UPDATE SET starts=excluded.starts",

                        (int(mid), int(pid_row), 0, int(start_flag))

                    )


    st.markdown("#### Current Squad")
    st.dataframe(df_match_squad(conn, int(mid)), use_container_width=True, hide_index=True)


def df_events(conn,mid:Optional[int]=None):
    if mid: return pd.read_sql_query("SELECT * FROM events WHERE match_id=? ORDER BY ts DESC",conn,params=(mid,))
    return pd.read_sql_query("SELECT * FROM events ORDER BY ts DESC",conn)


def page_logger(conn):
    st.header("Live Event Logger — Event First")

    # Undo bar
    last_ev = st.session_state.get("last_event")
    undo_cols = st.columns([0.7, 0.3])
    with undo_cols[0]:
        if last_ev:
            st.info(f"Last action: **{last_ev.get('label','event')}** → **{last_ev.get('player','')}** at {last_ev.get('time','')}")
        else:
            st.caption("No actions to undo yet.")
    with undo_cols[1]:
        if last_ev and st.button("Undo last action", type="secondary"):
            try:
                with conn:
                    conn.execute("DELETE FROM events WHERE id=?", (int(last_ev["id"]),))
                st.toast("Undone ✅", icon="↩️")
                st.session_state.pop("last_event", None)
                st.rerun()
            except Exception as e:
                st.error(f"Couldn't undo: {e}")

    matches = df_matches(conn)
    if matches.empty:
        st.info("Add a match first on the Matches page.")
        return

    mid = st.selectbox(
        "Match",
        matches["id"].astype(int).tolist(),
        format_func=lambda x: f"#{x} — {matches[matches['id']==x]['date'].iloc[0]} vs {matches[matches['id']==x]['opponent'].iloc[0]}",
    )

    squad = df_match_squad(conn, int(mid))
    if squad.empty:
        st.warning("No match squad set. Go to 'Match Squad' to assign jersey numbers.")
        return
    squad = squad.sort_values("shirt_number").reset_index(drop=True)

    # Quick filter for player grid
    filt = st.text_input("Filter players (name or number)", value="")
    if filt.strip():
        f = filt.strip().lower()
        squad = squad[[f in f"#{int(r['shirt_number'])} {r['name']}".lower() for _, r in squad.iterrows()]].reset_index(drop=True)

    mode = st.radio(
        "Input mode",
        ["Event → Player (faster)", "Player → Event (classic)"],
        index=0,
        horizontal=True
    )

    def _record_event(player_row, evt_code, label, value=1):
        with conn:
            cur = conn.execute(
                "INSERT INTO events(ts, match_id, player_id, event, value) VALUES(?,?,?,?,?)",
                (dt.datetime.now().isoformat(timespec="seconds"), int(mid), int(player_row["player_id"]), evt_code, int(value)),
            )
        st.session_state["last_event"] = {
            "id": int(cur.lastrowid),
            "label": label,
            "player": f"#{int(player_row['shirt_number'])} {player_row['name']}",
            "time": dt.datetime.now().strftime("%H:%M:%S"),
        }

    # Built-in groups
    GROUPS = [
        ("🟦 Scoring", [
            ("Try", "try"), ("Conversion", "conversion"), ("Penalty", "penalty"), ("Drop Goal", "drop_goal"), ("Assist", "assist")
        ]),
        ("🟩 Attack", [
            ("Carry Made", "carry_made"), ("Line Break", "line_break"), ("Offload", "offload"), ("Handling Error", "handling_error")
        ]),
        ("🟥 Defence", [
            ("Tackle Made", "tackle_made"), ("Tackle Missed", "tackle_missed"),
            ("Turnover Won", "turnover_won"), ("Turnover Conceded", "turnover_conceded"), ("Penalty Conceded", "penalty_conceded")
        ]),
        ("🟨 Kicking", [
            ("Kick (Gain)", "kick_gain"), ("Kick (No Gain)", "kick_no_gain")
        ]),
    ]

    # Append custom metrics groups (outside the list!)
    try:
        custom = get_custom_metrics(conn)
        if custom:
            by_group = {}
            for it in custom:
                if not bool(it.get("show_logger", True)):
                    continue
                by_group.setdefault(it.get("group","Custom"), []).append((it["label"], it["code"]))
            for gname, items in by_group.items():
                if items:
                    GROUPS.append((f"🟪 {gname}", items))
    except Exception:
        pass

    def group_header(title, color):
        st.markdown(
            f"<div style='margin:8px 0;padding:6px 10px;border-radius:8px;background:{color};color:#111;font-weight:600;'>{title}</div>",
            unsafe_allow_html=True
        )

    def render_button_group(items, key_prefix):
        per_row = 4
        for i in range(0, len(items), per_row):
            row = items[i:i+per_row]
            cols = st.columns(len(row))
            for c, (label, evt) in zip(cols, row):
                if c.button(label, key=f"{key_prefix}_{evt}"):
                    return evt, label
        return None, None

    if mode == "Event → Player (faster)":
        st.markdown("#### 1) Choose event")
        sel_evt = None; sel_label = None
        for title, items in GROUPS:
            if "Scoring" in title:
                color = "#e8f0ff"
            elif "Attack" in title:
                color = "#e8f7ec"
            elif "Defence" in title:
                color = "#feecec"
            else:
                color = "#fff8e1"
            group_header(title, color)
            evt, lab = render_button_group(items, "evt")
            if evt:
                sel_evt, sel_label = evt, lab

        if sel_evt:
            st.session_state["pending_event"] = sel_evt
            st.session_state["pending_event_label"] = sel_label
            st.toast(f"Event selected: {sel_label}", icon="✅")

        pen_evt = st.session_state.get("pending_event")
        if _is_match_locked(conn, int(mid)):
            st.error("This match is locked (read-only). Event logging is disabled.")
        elif pen_evt:
            st.markdown(f"#### 2) Assign **{st.session_state.get('pending_event_label','event')}** to a player")
            per_row = 5
            rows = (len(squad) + per_row - 1) // per_row
            idx = 0
            for r in range(rows):
                row_cols = st.columns(per_row)
                for c in range(per_row):
                    if idx >= len(squad):
                        break
                    rrow = squad.iloc[idx]
                    label = f"#{int(rrow['shirt_number'])} {rrow['name']}"
                    if row_cols[c].button(label, key=f"ply_{rrow['player_id']}_{pen_evt}"):
                        _record_event(rrow, pen_evt, st.session_state.get('pending_event_label','event'))
                        st.toast(f"Added {st.session_state.get('pending_event_label','event')} to {rrow['name']}", icon="✅")
                        log_action(conn,"event_add",{"match_id":int(mid),"player_id":int(rrow["player_id"]),"event":pen_evt,"value":1})
                        maybe_auto_backup(conn, label="add_event")
                        st.session_state.pop("pending_event", None)
                        st.session_state.pop("pending_event_label", None)
                        st.rerun()
                    idx += 1
        else:
            st.info("Pick an event above, then click the player.")

        st.markdown("#### Custom Event (optional)")
        c1, c2, c3 = st.columns(3)
        with c1:
            evt = st.selectbox("Type", EVENTS_CATALOG, key="custom_evt")
        with c2:
            val = st.number_input("Value", value=1, step=1, key="custom_val")
        with c3:
            pidx = st.selectbox(
                "Player",
                squad["player_id"].astype(int).tolist(),
                format_func=lambda x: (lambda r: f"#{int(r['shirt_number'])} — {r['name']}")(squad[squad['player_id']==x].iloc[0]),
                key="custom_player"
            )
            if _is_match_locked(conn, int(mid)):
                st.error("This match is locked (read-only).")
            elif st.button("Add Custom Event"):
                prow = squad[squad["player_id"]==pidx].iloc[0]
                _record_event(prow, evt, evt, value=val)
                st.success("Event added")
                log_action(conn,"event_add",{"match_id":int(mid),"event":evt,"value":int(val)})
                maybe_auto_backup(conn, label="add_event_custom")

    else:
        st.markdown("#### Player")
        pid = st.selectbox(
            "Player",
            squad["player_id"].astype(int).tolist(),
            format_func=lambda x: (lambda r: f"#{int(r['shirt_number'])} — {r['name']} ({r['position'] or '-'})")(squad[squad['player_id']==x].iloc[0])
        )
        st.markdown("#### Event")
        for title, items in GROUPS:
            if "Scoring" in title:
                color = "#e8f0ff"
            elif "Attack" in title:
                color = "#e8f7ec"
            elif "Defence" in title:
                color = "#feecec"
            else:
                color = "#fff8e1"
            group_header(title, color)
            evt, lab = render_button_group(items, "classic")
            if evt:
                prow = squad[squad["player_id"]==pid].iloc[0]
                _record_event(prow, evt, lab)
                st.success(f"Added {lab}")

        st.markdown("#### Custom Event")
        c1, c2 = st.columns(2)
        with c1:
            evt = st.selectbox("Type", EVENTS_CATALOG, key="classic_custom_evt")
            val = st.number_input("Value", value=1, step=1, key="classic_custom_val")
        with c2:
            if _is_match_locked(conn, int(mid)):
                st.error("This match is locked (read-only).")
            elif st.button("Add Event", key="classic_custom_add"):
                prow = squad[squad["player_id"]==pid].iloc[0]
                _record_event(prow, evt, evt, value=val)
                st.success("Event added")
                log_action(conn,"event_add",{"match_id":int(mid),"event":evt,"value":int(val)})
                maybe_auto_backup(conn, label="add_event_custom")

    st.markdown("#### Events for this Match")
    st.dataframe(df_events(conn, int(mid)), use_container_width=True, hide_index=True)

    st.markdown("---")
    if _is_match_locked(conn, int(mid)):
        st.error("This match is locked (read-only). Aggregation is disabled.")
    elif st.button("Aggregate Events → Player Match Stats"):
        aggregate_events_to_stats(conn, int(mid))
        st.success("Aggregated. Edit minutes/starts on the Stats page.")
        log_action(conn,"aggregate_stats",{"match_id":int(mid)})
        maybe_auto_backup(conn, label="aggregate")



def page_stats(conn):
    st.header("Stats (Edit minutes/starts; view totals)")
    matches=df_matches(conn)
    if matches.empty: st.info("Add a match first."); return
    mid=st.selectbox("Match",matches["id"].astype(int).tolist(),format_func=lambda x: f"#{x} — {matches[matches['id']==x]['date'].iloc[0]} vs {matches[matches['id']==x]['opponent'].iloc[0]}")
    df=pd.read_sql_query("""SELECT p.id as player_id,p.name,p.position,COALESCE(s.minutes,0) as minutes,COALESCE(s.starts,0) as starts,COALESCE(s.tries,0) as tries,COALESCE(s.conversions,0) as conversions,COALESCE(s.penalties,0) as penalties,COALESCE(s.drop_goals,0) as drop_goals,COALESCE(s.carries_made,0) as carries_made,COALESCE(s.tackles_made,0) as tackles_made,COALESCE(s.tackles_missed,0) as tackles_missed,COALESCE(s.turnovers_won,0) as turnovers_won,COALESCE(s.turnovers_conceded,0) as turnovers_conceded,COALESCE(s.line_breaks,0) as line_breaks,COALESCE(s.offloads,0) as offloads,COALESCE(s.handling_errors,0) as handling_errors,COALESCE(s.kick_gain,0) as kick_gain,COALESCE(s.kick_no_gain,0) as kick_no_gain,COALESCE(s.penalties_conceded,0) as penalties_conceded,COALESCE(s.assists,0) as assists,ms.shirt_number as shirt_number, ms.starting as starting FROM players p LEFT JOIN player_match_stats s ON s.player_id=p.id AND s.match_id=? LEFT JOIN match_squad ms ON ms.player_id=p.id AND ms.match_id=? WHERE p.active=1 ORDER BY p.name""", conn, params=(int(mid), int(mid)))
    edited=st.data_editor(df[["player_id","name","minutes","starts"]],num_rows="fixed",use_container_width=True)
    if _is_match_locked(conn, int(mid)):
        st.error("This match is locked (read-only). Editing minutes/starts is disabled.")
    elif st.button("Save Minutes/Starts"):
        with conn:
            for _,row in edited.iterrows():
                conn.execute("INSERT INTO player_match_stats(match_id,player_id,minutes,starts) VALUES(?,?,?,?) ON CONFLICT(match_id,player_id) DO UPDATE SET minutes=excluded.minutes,starts=excluded.starts",(int(mid),int(row["player_id"]),int(row["minutes"]),int(row["starts"])))
        st.success("Saved minutes/starts")
        log_action(conn,"stats_save",{"match_id":int(mid)})
        maybe_auto_backup(conn, label="save_minutes_starts")
    pts=get_points(conn); df["points"]=df.apply(lambda r: r["tries"]*pts["try"]+r["conversions"]*pts["conversion"]+r["penalties"]*pts["penalty"]+r["drop_goals"]*pts["drop_goal"],axis=1)
    st.dataframe(df.drop(columns=["player_id"]).set_index("name"),use_container_width=True)



def page_audit(conn):
    st.header("Audit Log")
    df = pd.read_sql_query("SELECT ts, username, role, action, details FROM audit_log ORDER BY ts DESC", conn)
    # Filters
    col1, col2, col3 = st.columns(3)
    with col1:
        user_f = st.text_input("User filter").strip().lower()
    with col2:
        action_f = st.text_input("Action filter").strip().lower()
    with col3:
        recent_only = st.checkbox("Last 7 days only", value=False)
    if not df.empty:
        if user_f:
            df = df[df["username"].str.lower().str.contains(user_f, na=False)]
        if action_f:
            df = df[df["action"].str.lower().str.contains(action_f, na=False)]
        if recent_only:
            cutoff = (dt.datetime.now() - dt.timedelta(days=7)).isoformat()
            df = df[df["ts"] >= cutoff]
    st.dataframe(df, use_container_width=True, hide_index=True)
    # CSV export
    csv = df.to_csv(index=False).encode("utf-8")
    st.download_button("Download audit CSV", csv, file_name="audit_log.csv", mime="text/csv")


def page_settings(conn):
    st.header("Settings & Branding")

    st.subheader("Branding")
    logo_b64, primary = get_branding(conn)
    col1, col2 = st.columns([2,1])
    with col1:
        uploaded = st.file_uploader("Upload logo (PNG/JPG)", type=["png","jpg","jpeg"])
        if uploaded is not None:
            data = uploaded.read()
            set_setting(conn, "branding.logo_b64", base64.b64encode(data).decode("utf-8"))
            st.success("Logo saved")
            log_action(conn,"branding_logo",{}); maybe_auto_backup(conn, label="logo_upload"); st.rerun()
        if logo_b64:
            st.image(io.BytesIO(base64.b64decode(logo_b64)), caption="Current logo", use_column_width=False)
    with col2:
        new_primary = st.color_picker("Primary colour", value=primary)
        if st.button("Save colour"):
            set_setting(conn, "branding.primary", new_primary)
            st.success("Primary colour updated")
            log_action(conn,"branding_colour",{}); maybe_auto_backup(conn, label="brand_colour"); st.rerun()


    st.divider()
    st.subheader("Cloud Backup — Dropbox")
    tok, fold, auto = get_dropbox_settings(conn)
    with st.form("dropbox_form"):
        t = st.text_input("Dropbox access token", value=tok, type="password", help="Generate a token in your Dropbox App; App folder or full access both work.")
        f = st.text_input("Backup folder path", value=fold, help="e.g. /Apps/RugbyStats/backups")
        a = st.checkbox("Auto-backup on changes", value=auto)
        saveb = st.form_submit_button("Save backup settings")
        if saveb:
            set_dropbox_settings(conn, t, f, a); st.success("Dropbox settings saved")
    c1, c2 = st.columns(2)

    st.divider()
    st.subheader("Nightly backup")
    _status_ok, _status_try, _sched_time, _sched_on = get_backup_status(conn)
    colA, colB = st.columns([1,2])
    with colA:
        enable_nightly = st.checkbox("Enable nightly backup", value=_sched_on)
    with colB:
        time_pick = st.text_input("Backup time (HH:MM, 24h)", value=_sched_time)
    if st.button("Save schedule"):
        set_backup_schedule(conn, enabled=enable_nightly, time_str=time_pick)
        st.success("Nightly backup schedule saved")

    st.subheader("Restore from Dropbox")

    st.subheader("Local backup / restore")
    colx, coly = st.columns(2)
    with colx:
        # Download current DB
        try:
            with open(DB_FILE, "rb") as _f:
                _db_bytes = _f.read()
        except Exception as _e:
            _db_bytes = b""
        st.download_button("Download current database (.db)", data=_db_bytes, file_name=os.path.basename(DB_FILE), mime="application/octet-stream")
    with coly:
        up = st.file_uploader("Restore from local .db file", type=["db"])
        if up is not None and st.button("Restore uploaded file"):
            data = up.read()
            with open(DB_FILE, "wb") as _f:
                _f.write(data)
            try:
                get_conn.clear()  # reset cached connection
            except Exception:
                pass
            st.success("Database restored from uploaded file. Reloading...")
            st.rerun()

    st.subheader("External pinger (for Streamlit Cloud)")
    st.caption("Use these URLs in a monitoring service (e.g., UptimeRobot) to wake the app or trigger a backup. Keep the token secret.")
    tok = get_pinger_token(conn)
    app_url = st.text_input("Your app base URL (paste your deployed URL here)", value="", help="Example: https://yourname-yourrepo.streamlit.app")
    if app_url:
        st.code(app_url + f"?ping=1", language="bash")
        st.code(app_url + f"?backup=1&token={tok}", language="bash")
    if st.button("Rotate pinger token"):
        new_tok = rotate_pinger_token(conn)
        st.success("Token rotated. Update your monitor to the new URL.")

    st.caption("Pick a versioned backup to restore. This will overwrite the current database. The app will reload.")
    token, folder, _ = get_dropbox_settings(conn)
    if not token:
        st.info("Set your Dropbox token above to enable restore.")
    else:
        try:
            import dropbox  # type: ignore
            dbx = dropbox.Dropbox(token)
            listing = dbx.files_list_folder(folder)
            # Filter for .db files, newest first
            entries = [e for e in listing.entries if hasattr(e, 'name') and e.name.endswith('.db')]
            entries.sort(key=lambda e: getattr(e, 'server_modified', dt.datetime.min), reverse=True)
            names = [e.name for e in entries]
            choice = st.selectbox("Backup file", names)
            if st.button("Restore selected backup"):
                sel = next((e for e in entries if e.name == choice), None)
                if sel:
                    _, res = dbx.files_download(sel.path_lower)
                    data = res.content
                    # Write to DB file
                    with open(DB_FILE, "wb") as f:
                        f.write(data)
                    # Clear connection cache and reload app
                    try:
                        get_conn.clear()  # type: ignore
                    except Exception:
                        pass
                    st.success(f"Restored {choice}. Reloading...")
                    st.rerun()
        except Exception as e:
            st.error(f"Restore listing failed: {e}")

    with c1:
        if st.button("Backup now to Dropbox"):
            ok = backup_db_to_dropbox(conn, label="manual")
            st.success("Backed up to Dropbox")
            log_action(conn,"backup_now",{}) if ok else st.error("Backup failed (see message above).")
    with c2:
        st.caption("Tip: Auto-backup triggers after key changes (squad save, logging events, etc).")

    st.divider()

    st.divider()
    st.subheader("Dependencies")
    st.caption("If a package is missing, click Install. If that fails, run 'pip install -r requirements.txt' in a terminal.")
    _st = deps_status()
    for mod, ok in _st.items():
        cols = st.columns([0.4,0.4,0.2])
        with cols[0]:
            st.write(mod)
        with cols[1]:
            st.write("✅ Installed" if ok else "❌ Missing")
        with cols[2]:
            if not ok:
                spec = REQUIRED_PACKAGES[mod]
                if st.button(f"Install", key=f"dep_install_{mod}"):
                    if _pip_install(spec): st.rerun()

    
    st.divider()
    st.subheader("Metrics (Custom)")
    st.caption("Add or edit custom measurable parameters. Visibility controls let you show them in the Live Logger and/or Reports.")
    curr = get_custom_metrics(conn)
    if "metrics_edit" not in st.session_state:
        st.session_state["metrics_edit"] = curr.copy()
    ed = st.session_state["metrics_edit"]
    if ed:
        for i, m in enumerate(ed):
            c1,c2,c3,c4,c5,c6 = st.columns([0.18,0.28,0.22,0.12,0.1,0.1])
            with c1: m["code"] = st.text_input(f"Code {i+1}", value=m["code"], key=f"mc_code_{i}")
            with c2: m["label"] = st.text_input(f"Label {i+1}", value=m["label"], key=f"mc_label_{i}")
            with c3: m["group"] = st.text_input(f"Group {i+1}", value=m.get("group","Custom"), key=f"mc_group_{i}")
            with c4: m["show_logger"]  = st.checkbox("Logger",  value=bool(m.get("show_logger", True)), key=f"mc_log_{i}")
            with c5: m["show_reports"] = st.checkbox("Reports", value=bool(m.get("show_reports", True)), key=f"mc_rep_{i}")
            with c6:
                if st.button("Remove", key=f"mc_remove_{i}"):
                    ed.pop(i); st.rerun()
    with st.expander("Add new metric"):
        nc, nl, ng = st.columns([0.25,0.35,0.4])
        with nc: code_new = st.text_input("Code", placeholder="e.g., ruck_hit")
        with nl: label_new = st.text_input("Label", placeholder="e.g., Ruck Hit")
        with ng: group_new = st.text_input("Group", value="Custom")
        if st.button("Add metric"):
            if code_new.strip() and label_new.strip():
                ed.append({"code": code_new.strip(), "label": label_new.strip(), "group": group_new.strip() or "Custom", "show_logger": True, "show_reports": True})
                st.success("Added. Scroll up to review."); st.rerun()
            else:
                st.error("Code and Label are required.")
    if st.button("Save metrics"):
        if set_custom_metrics(conn, ed):
            st.success("Custom metrics saved"); st.rerun()
        else:
            st.error("Could not save metrics")

    st.subheader("Scoring Points")
    pts = get_points(conn)
    with st.form("points_form"):
        c1, c2, c3, c4 = st.columns(4)
        with c1: t = st.number_input("Try", min_value=1, value=int(pts["try"]))
        with c2: c = st.number_input("Conversion", min_value=1, value=int(pts["conversion"]))
        with c3: p = st.number_input("Penalty", min_value=1, value=int(pts["penalty"]))
        with c4: d = st.number_input("Drop Goal", min_value=1, value=int(pts["drop_goal"]))
        if st.form_submit_button("Save points"):
            set_points(conn, {"try":t, "conversion":c, "penalty":p, "drop_goal":d})
            st.success("Points saved")
            log_action(conn,"points_update",{})
            maybe_auto_backup(conn, label="points_saved")

    st.divider()
    st.subheader("User Management (Admin)")
    user = st.session_state.get("user")
    if has_role(user, "Admin"):
        tab1, tab2 = st.tabs(["Add user", "Manage users"])
        with tab1:
            with st.form("add_user_form"):
                nu = st.text_input("Username")
                nr = st.selectbox("Role", ["Admin","Coach","Analyst","Viewer"])
                npw = st.text_input("Password", type="password")
                if st.form_submit_button("Create user"):
                    if not nu.strip() or not npw:
                        st.error("Username and password required.")
                    else:
                        salt = _get_salt(conn)
                        try:
                            with conn:
                                conn.execute("INSERT INTO users(username, password_hash, role, active) VALUES(?,?,?,1)",
                                             (nu.strip(), _hash_pw_bcrypt(npw), nr))
                            st.success("User created")
                            log_action(conn,"user_create",{"username":nu,"role":nr})
                            maybe_auto_backup(conn, label="user_created")
                        except Exception as e:
                            st.error(f"Could not create user: {e}")
        with tab2:
            users_df = pd.read_sql_query("SELECT id, username, role, active FROM users ORDER BY username", conn)
            st.dataframe(users_df, use_container_width=True, hide_index=True)
            uid = st.selectbox("Select user to modify", users_df["id"].tolist() if not users_df.empty else [])
            if uid:
                colA, colB, colC = st.columns(3)
                with colA:
                    new_role = st.selectbox("New role", ["Admin","Coach","Analyst","Viewer"])
                    if st.button("Update role"):
                        with conn: conn.execute("UPDATE users SET role=? WHERE id=?", (new_role, int(uid)))
                        st.success("Role updated")
                        log_action(conn,"user_role",{"user_id":int(uid),"role":new_role}); maybe_auto_backup(conn, label="user_role"); st.rerun()
                with colB:
                    npw2 = st.text_input("Reset password", type="password", key="pwreset")
                    if st.button("Set password"):
                        if npw2:
                            salt = _get_salt(conn)
                            with conn: conn.execute("UPDATE users SET password_hash=? WHERE id=?", (_hash_pw_bcrypt(npw2), int(uid)))
                            st.success("Password updated")
                            log_action(conn,"user_pw",{"user_id":int(uid)})
                            maybe_auto_backup(conn, label="user_pw")
                with colC:
                    if st.button("Toggle active"):
                        with conn: conn.execute("UPDATE users SET active = 1 - active WHERE id=?", (int(uid),))
                        st.success("Toggled active")
                        log_action(conn,"user_active_toggle",{"user_id":int(uid)}); maybe_auto_backup(conn, label="user_active"); st.rerun()
    else:
        st.info("Only Admins can manage users.")



def page_reports(conn):
    st.header("Leaderboards & Season Reports")
    pts=get_points(conn)
    team=pd.read_sql_query("""SELECT p.name,p.position,COALESCE(SUM(s.minutes),0) as minutes,COALESCE(SUM(s.starts),0) as starts,COALESCE(SUM(s.tries),0) as tries,COALESCE(SUM(s.conversions),0) as conversions,COALESCE(SUM(s.penalties),0) as penalties,COALESCE(SUM(s.drop_goals),0) as drop_goals,COALESCE(SUM(s.carries_made),0) as carries_made,COALESCE(SUM(s.tackles_made),0) as tackles_made,COALESCE(SUM(s.tackles_missed),0) as tackles_missed,COALESCE(SUM(s.turnovers_won),0) as turnovers_won,COALESCE(SUM(s.turnovers_conceded),0) as turnovers_conceded,COALESCE(SUM(s.line_breaks),0) as line_breaks,COALESCE(SUM(s.offloads),0) as offloads,COALESCE(SUM(s.handling_errors),0) as handling_errors,COALESCE(SUM(s.kick_gain),0) as kick_gain,COALESCE(SUM(s.kick_no_gain),0) as kick_no_gain, COALESCE(SUM(s.penalties_conceded),0) as penalties_conceded,COALESCE(SUM(s.assists),0) as assists FROM players p LEFT JOIN player_match_stats s ON s.player_id=p.id WHERE p.active=1 GROUP BY p.id ORDER BY p.name""",conn)
    team["points"]=team.apply(lambda r: r["tries"]*pts["try"]+r["conversions"]*pts["conversion"]+r["penalties"]*pts["penalty"]+r["drop_goals"]*pts["drop_goal"],axis=1)
    st.subheader("Attack"); st.dataframe(team[["name","position","tries","assists","carries_made","line_breaks","offloads","handling_errors"]].set_index("name"),use_container_width=True)
    st.subheader("Defence"); st.dataframe(team[["name","position","tackles_made","tackles_missed","turnovers_won","turnovers_conceded"]].set_index("name"),use_container_width=True)
    st.subheader("Kicking"); st.dataframe(team[["name","position","kick_gain","kick_no_gain","penalties_conceded"]].set_index("name"),use_container_width=True)
    
    st.subheader("Overall & Minutes")
    overall_cols = ["minutes","starts","points","tries","conversions","penalties","drop_goals",
                    "carries_made","line_breaks","offloads","handling_errors",
                    "tackles_made","tackles_missed","turnovers_won","turnovers_conceded",
                    "penalties_conceded","kick_gain","kick_no_gain","assists"]
    st.dataframe(team[["name","position"] + overall_cols].set_index("name"), use_container_width=True)
    # Export Overall & Minutes
    overall_csv = team[["name","position"] + overall_cols].to_csv(index=False).encode("utf-8")
    st.download_button("Download Overall & Minutes (CSV)", overall_csv, file_name="overall_minutes.csv", mime="text/csv")

    # Per 80 table (rate per 80 minutes)
    rate_cols = [c for c in overall_cols if c not in ["minutes","starts","points"]]
    per80 = team.copy()
    for c in rate_cols:
        per80[c] = per80.apply(lambda r: (r[c] / r["minutes"] * 80) if r["minutes"] else 0.0, axis=1)
    st.subheader("Per 80 minutes (Rates)")
    st.dataframe(per80[["name","position"] + rate_cols].set_index("name"), use_container_width=True)
    # Export Per 80
    per80_csv = per80[["name","position"] + rate_cols].to_csv(index=False).encode("utf-8")
    st.download_button("Download Per 80 (CSV)", per80_csv, file_name="per80_rates.csv", mime="text/csv")
    # --- Team totals by match ---
    st.subheader("Team Totals by Match")
    sql_team_match = """
        SELECT
            m.id as match_id,
            m.date,
            m.opponent,
            m.competition,
            m.location,
            m.team_score,
            m.opp_score,
            COALESCE(SUM(s.minutes),0) as minutes,
            COALESCE(SUM(s.starts),0) as starts,
            COALESCE(SUM(s.tries),0) as tries,
            COALESCE(SUM(s.conversions),0) as conversions,
            COALESCE(SUM(s.penalties),0) as penalties,
            COALESCE(SUM(s.drop_goals),0) as drop_goals,
            COALESCE(SUM(s.carries_made),0) as carries_made,
            COALESCE(SUM(s.line_breaks),0) as line_breaks,
            COALESCE(SUM(s.offloads),0) as offloads,
            COALESCE(SUM(s.handling_errors),0) as handling_errors,
            COALESCE(SUM(s.tackles_made),0) as tackles_made,
            COALESCE(SUM(s.tackles_missed),0) as tackles_missed,
            COALESCE(SUM(s.turnovers_won),0) as turnovers_won,
            COALESCE(SUM(s.turnovers_conceded),0) as turnovers_conceded,
            COALESCE(SUM(s.penalties_conceded),0) as penalties_conceded,
            COALESCE(SUM(s.kick_gain),0) as kick_gain,
            COALESCE(SUM(s.kick_no_gain),0) as kick_no_gain,
            COALESCE(SUM(s.assists),0) as assists
        FROM matches m
        LEFT JOIN player_match_stats s ON s.match_id = m.id
        GROUP BY m.id
        ORDER BY m.date DESC
    """
    team_match = pd.read_sql_query(sql_team_match, conn)
    team_match["points"] = team_match.apply(
        lambda r: r["tries"]*pts["try"] + r["conversions"]*pts["conversion"] + r["penalties"]*pts["penalty"] + r["drop_goals"]*pts["drop_goal"],
        axis=1
    )
    cols = ["date","opponent","competition","location","team_score","opp_score",
            "points","tries","conversions","penalties","drop_goals",
            "carries_made","line_breaks","offloads","handling_errors",
            "tackles_made","tackles_missed","turnovers_won","turnovers_conceded","penalties_conceded",
            "kick_gain","kick_no_gain","assists","minutes","starts"]
    st.dataframe(team_match[cols], use_container_width=True)
    # Export Team Totals by Match
    team_match_csv = team_match[cols].to_csv(index=False).encode("utf-8")
    st.download_button("Download Team Totals by Match (CSV)", team_match_csv, file_name="team_totals_by_match.csv", mime="text/csv")
    # Season Totals (aggregate across all matches)
    st.subheader("Season Totals")
    # Sum over player_match_stats directly for robustness
    season_sql = """
        SELECT
            COALESCE(SUM(minutes),0) as minutes,
            COALESCE(SUM(starts),0) as starts,
            COALESCE(SUM(tries),0) as tries,
            COALESCE(SUM(conversions),0) as conversions,
            COALESCE(SUM(penalties),0) as penalties,
            COALESCE(SUM(drop_goals),0) as drop_goals,
            COALESCE(SUM(carries_made),0) as carries_made,
            COALESCE(SUM(line_breaks),0) as line_breaks,
            COALESCE(SUM(offloads),0) as offloads,
            COALESCE(SUM(handling_errors),0) as handling_errors,
            COALESCE(SUM(tackles_made),0) as tackles_made,
            COALESCE(SUM(tackles_missed),0) as tackles_missed,
            COALESCE(SUM(turnovers_won),0) as turnovers_won,
            COALESCE(SUM(turnovers_conceded),0) as turnovers_conceded,
            COALESCE(SUM(penalties_conceded),0) as penalties_conceded,
            COALESCE(SUM(kick_gain),0) as kick_gain,
            COALESCE(SUM(kick_no_gain),0) as kick_no_gain,
            COALESCE(SUM(assists),0) as assists
        FROM player_match_stats
    """
    season = pd.read_sql_query(season_sql, conn)
    season["points"] = season.apply(
        lambda r: r["tries"]*pts["try"] + r["conversions"]*pts["conversion"] + r["penalties"]*pts["penalty"] + r["drop_goals"]*pts["drop_goal"],
        axis=1
    )
    season_cols = ["points","tries","conversions","penalties","drop_goals","carries_made","line_breaks","offloads","handling_errors","tackles_made","tackles_missed","turnovers_won","turnovers_conceded","penalties_conceded","kick_gain","kick_no_gain","assists","minutes","starts"]
    st.dataframe(season[season_cols], use_container_width=True)
    # Export Season Totals
    season_csv = season[season_cols].to_csv(index=False).encode("utf-8")
    st.download_button("Download Season Totals (CSV)", season_csv, file_name="season_totals.csv", mime="text/csv")
    # Excel export (multi-sheet)
    import pandas as _pd
    from io import BytesIO as _BytesIO
    xls_buf = _BytesIO()
    import importlib
    if importlib.util.find_spec("xlsxwriter") is None:
        st.warning("Excel export requires the package 'xlsxwriter'. Go to Settings → Dependencies to install it.")
    else:
        with _pd.ExcelWriter(xls_buf, engine="xlsxwriter") as writer:
            team[["name","position"] + overall_cols].to_excel(writer, index=False, sheet_name="Overall & Minutes")
            try:
                per80[["name","position"] + rate_cols].to_excel(writer, index=False, sheet_name="Per 80 (Built-in)")
            except Exception:
                pass
            team_match[cols].to_excel(writer, index=False, sheet_name="Team Totals by Match")
            season[season_cols].to_excel(writer, index=False, sheet_name="Season Totals")
            # Custom Per-80 if available
            try:
                mins = pd.read_sql_query(
                    "SELECT player_id, COALESCE(SUM(minutes),0) as minutes FROM player_match_stats GROUP BY player_id",
                    conn
                )
                name_map = pd.read_sql_query("SELECT id as player_id, name, position FROM players", conn)
                mins = mins.merge(name_map, on="player_id", how="right").fillna({"minutes":0})
                totals = pd.read_sql_query(
                    "SELECT p.id as player_id, p.name, p.position, t.metric_code, SUM(t.total) as total "
                    "FROM player_match_metric_totals t JOIN players p ON p.id=t.player_id "
                    "GROUP BY p.id, t.metric_code",
                    conn
                )
                if not totals.empty:
                    per80c = totals.merge(mins[["player_id","minutes"]], on="player_id", how="left")
                    per80c["per80"] = per80c.apply(lambda r: (r["total"]/r["minutes"]*80) if r["minutes"] else 0.0, axis=1)
                    piv80c = per80c.pivot_table(index=["name","position"], columns="metric_code", values="per80", aggfunc="sum", fill_value=0).reset_index()
                    piv80c.to_excel(writer, index=False, sheet_name="Per 80 (Custom)")
            except Exception:
                pass
        st.download_button("Download All Reports (Excel)", data=xls_buf.getvalue(), file_name="rugby_reports.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


    
    metric=st.selectbox("Leaderboard metric",["points","tries","assists","carries_made","line_breaks","offloads","handling_errors","tackles_made","tackles_missed","turnovers_won","turnovers_conceded","kick_gain","kick_no_gain","penalties_conceded"],index=0)
    top_n=st.slider("Top N",3,20,10); lb=team[["name","points"]].rename(columns={"points":"value"}) if metric=="points" else team[["name",metric]].rename(columns={metric:"value"})
    st.dataframe(lb.sort_values("value",ascending=False).head(top_n).set_index("name"),use_container_width=True)
    # --- Custom Metrics — Season (Per Player) ---
    st.subheader("Custom Metrics — Season (Per Player)")
    cm = pd.read_sql_query(
        "SELECT p.name, p.position, t.metric_code, SUM(t.total) as total FROM player_match_metric_totals t JOIN players p ON p.id=t.player_id GROUP BY p.id, t.metric_code ORDER BY p.name, t.metric_code",
        conn
    )
    if cm.empty:
        st.info("No custom metric data yet. Add custom metrics in Settings and log events in the Live Logger.")
    else:
        _cm_meta = {m["code"]: m for m in get_custom_metrics(conn)}
        cm = cm[cm["metric_code"].apply(lambda c: _cm_meta.get(c, {}).get("show_reports", True))]
        piv = cm.pivot_table(index=["name","position"], columns="metric_code", values="total", aggfunc="sum", fill_value=0).reset_index()
        st.dataframe(piv.set_index("name"), use_container_width=True)
        cm_csv = piv.to_csv(index=False).encode("utf-8")
        st.download_button("Download Custom Metrics (CSV)", cm_csv, file_name="custom_metrics_players.csv", mime="text/csv")

        # Per-80 for custom metrics
        mins = pd.read_sql_query("SELECT player_id, COALESCE(SUM(minutes),0) as minutes FROM player_match_stats GROUP BY player_id", conn)
        name_map = pd.read_sql_query("SELECT id as player_id, name, position FROM players", conn)
        mins = mins.merge(name_map, on="player_id", how="right").fillna({"minutes":0})
        totals = pd.read_sql_query(
            "SELECT p.id as player_id, p.name, p.position, t.metric_code, SUM(t.total) as total FROM player_match_metric_totals t JOIN players p ON p.id=t.player_id GROUP BY p.id, t.metric_code",
            conn
        )
        if not totals.empty:
            per80 = totals.merge(mins[["player_id","minutes"]], on="player_id", how="left")
            per80["per80"] = per80.apply(lambda r: (r["total"]/r["minutes"]*80) if r["minutes"] else 0.0, axis=1)
            piv80 = per80.pivot_table(index=["name","position"], columns="metric_code", values="per80", aggfunc="sum", fill_value=0).reset_index()
            st.subheader("Custom Metrics — Per 80 minutes (Per Player)")
            st.dataframe(piv80.set_index("name"), use_container_width=True)
            dl80 = piv80.to_csv(index=False).encode("utf-8")
            st.download_button("Download Custom Metrics Per80 (CSV)", dl80, file_name="custom_metrics_per80_players.csv", mime="text/csv")

    # --- Custom Metrics — Team Totals by Match ---
    st.subheader("Custom Metrics — Team Totals by Match")
    cmm = pd.read_sql_query(
        "SELECT m.date, m.opponent, t.metric_code, SUM(t.total) as total FROM player_match_metric_totals t JOIN matches m ON m.id=t.match_id GROUP BY t.match_id, t.metric_code ORDER BY m.date DESC, t.metric_code",
        conn
    )
    if not cmm.empty:
        _cm_meta = {m["code"]: m for m in get_custom_metrics(conn)}
        cmm = cmm[cmm["metric_code"].apply(lambda c: _cm_meta.get(c, {}).get("show_reports", True))]
        pivm = cmm.pivot_table(index=["date","opponent"], columns="metric_code", values="total", aggfunc="sum", fill_value=0).reset_index()
        st.dataframe(pivm, use_container_width=True)
        cmm_csv = pivm.to_csv(index=False).encode("utf-8")
        st.download_button("Download Custom Metrics by Match (CSV)", cmm_csv, file_name="custom_metrics_matches.csv", mime="text/csv")


def main():
    st.set_page_config(page_title="Rugby Stats v3y",layout="wide"); conn=get_conn()
    st.sidebar.title("Rugby Stats v3s"); page=st.sidebar.radio("Navigate",["Players","Matches","Match Squad","Live Logger","Stats","Reports"],index=2)
    if page=="Players": page_players(conn)
    elif page=="Matches": page_matches(conn)
    elif page=="Match Squad": page_squad(conn)
    elif page=="Live Logger": page_logger(conn)
    elif page=="Stats": page_stats(conn)
    elif page=="Reports": page_reports(conn)
    elif page=="Settings": page_settings(conn)
    elif page=="Audit": page_audit(conn)

if __name__=="__main__": main()
