import os, io, sqlite3, datetime as dt
import pandas as pd
import streamlit as st
import altair as alt
import requests
from components_video_hotkeys import video_hotkeys

DB_FILE = os.environ.get("RUGBY_DB_PATH", "/mount/data/rugby_stats.db")

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS players(id INTEGER PRIMARY KEY, name TEXT NOT NULL, position TEXT, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS metrics(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, label TEXT NOT NULL, group_name TEXT NOT NULL, type TEXT NOT NULL DEFAULT 'count', per80 INTEGER NOT NULL DEFAULT 1, weight REAL, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS matches(id INTEGER PRIMARY KEY, opponent TEXT NOT NULL, date TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, match_id INTEGER NOT NULL, player_id INTEGER NOT NULL, metric_id INTEGER NOT NULL, value REAL NOT NULL DEFAULT 1, ts TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS videos(id INTEGER PRIMARY KEY, match_id INTEGER NOT NULL, kind TEXT NOT NULL, url TEXT NOT NULL, label TEXT NOT NULL, offset REAL NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS moments(id INTEGER PRIMARY KEY, match_id INTEGER NOT NULL, video_id INTEGER NOT NULL, video_ts REAL NOT NULL, note TEXT DEFAULT '', ts TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS hotkeys(key TEXT PRIMARY KEY, metric_id INTEGER NOT NULL);
"""

DEFAULT_METRICS=[
    ("carries_made","Carries Made","Attack", 1.0),
    ("tackles_made","Tackles Made","Defense", 1.0),
    ("tackles_missed","Tackles Missed","Defense", -1.0),
    ("turnovers_won","Turnovers Won","Defense", 4.0),
    ("turnovers_conceded","Turnovers Conceded","Discipline", -2.0),
    ("line_breaks","Line Breaks","Attack", 3.0),
    ("offloads","Offloads","Attack", 1.0),
    ("handling_errors","Handling Errors","Attack", -1.0),
    ("kick_gain","Kick w/ Territory Gain","Kicking", 1.0),
    ("kick_no_gain","Kick w/o Territory Gain","Kicking", 0.0),
    ("tries","Tries","Scoring", 5.0),
    ("conversions","Conversions","Scoring", 2.0),
    ("penalties","Penalties Scored","Scoring", 3.0),
    ("drop_goals","Drop Goals","Scoring", 4.0),
    ("assists","Assists","Attack", 2.0),
    ("penalties_conceded","Penalties Conceded","Discipline", -2.0),
]

def get_conn():
    dp=os.path.dirname(DB_FILE)
    if dp and dp not in ("/",""):
        try: os.makedirs(dp, exist_ok=True)
        except PermissionError: pass
    c=sqlite3.connect(DB_FILE, check_same_thread=False); c.row_factory=sqlite3.Row
    with c: c.executescript(SCHEMA)
    if c.execute("SELECT COUNT(*) FROM metrics").fetchone()[0]==0:
        with c:
            for key,label,grp,w in DEFAULT_METRICS:
                c.execute("INSERT OR IGNORE INTO metrics(name,label,group_name,per80,weight,active) VALUES(?,?,?,?,?,1)", (key,label,grp,1,w))
    c.execute("UPDATE metrics SET weight=COALESCE(weight,0)")
    c.commit()
    return c

def gate(role, allowed):
    if role not in allowed:
        st.warning("You do not have permission for this action."); st.stop()

def _metric_id_by_label(conn, label):
    r=conn.execute("SELECT id FROM metrics WHERE label=?", (label,)).fetchone()
    return int(r[0]) if r else None

# ---------- Players ----------
def page_players(conn, role):
    st.header("Players")
    df=pd.read_sql_query("SELECT id,name,position,active FROM players ORDER BY name", conn)
    st.dataframe(df, use_container_width=True)
    if role in ("admin","editor"):
        with st.expander("Add Player"):
            name=st.text_input("Name"); pos=st.text_input("Position")
            if st.button("Add"):
                if not name: st.error("Enter a name.")
                else:
                    with conn: conn.execute("INSERT INTO players(name,position,active) VALUES(?,?,1)", (name,pos))
                    st.success("Player added"); st.rerun()
        with st.expander("Edit / Deactivate"):
            if not df.empty:
                pid=st.selectbox("Select player", df["id"].tolist(), format_func=lambda x: df.loc[df["id"]==x,"name"].iloc[0])
                col1,col2,col3=st.columns(3)
                with col1: new_name=st.text_input("Name", value=df.loc[df["id"]==pid,"name"].iloc[0])
                with col2: new_pos=st.text_input("Position", value=df.loc[df["id"]==pid,"position"].iloc[0] or "")
                with col3: new_active=st.checkbox("Active", value=bool(df.loc[df["id"]==pid,"active"].iloc[0]))
                if st.button("Save changes"):
                    with conn: conn.execute("UPDATE players SET name=?, position=?, active=? WHERE id=?", (new_name,new_pos,int(new_active),pid))
                    st.success("Saved"); st.rerun()
        with st.expander("Delete Player (danger)"):
            if not df.empty:
                del_id=st.selectbox("Player to delete", df["id"].tolist(), format_func=lambda x: df.loc[df["id"]==x,"name"].iloc[0])
                if st.button("Delete permanently", type="primary"):
                    with conn: conn.execute("DELETE FROM players WHERE id=?", (del_id,))
                    st.warning("Deleted"); st.rerun()
    else:
        st.info("Read-only: login as admin/editor to edit players.")

# ---------- Metrics ----------
def page_metrics(conn, role):
    gate(role, ("admin",))
    st.header("Metrics (Custom + Weights)")
    mdf=pd.read_sql_query("SELECT id,name,label,group_name,type,per80,weight,active FROM metrics ORDER BY group_name,label", conn)
    st.dataframe(mdf, use_container_width=True)
    with st.expander("Add Metric"):
        key=st.text_input("Key (snake_case)", placeholder="dominant_tackles")
        label=st.text_input("Label", placeholder="Dominant Tackles")
        grp=st.selectbox("Group", ["Attack","Defense","Kicking","Discipline","Scoring","Other"])
        per80=st.checkbox("Include in per-80", value=True)
        weight=st.number_input("Leaderboard Weight (can be negative)", value=0.0, step=0.5)
        if st.button("Create Metric"):
            if not key or not label: st.error("Key and Label required.")
            else:
                try:
                    with conn: conn.execute("INSERT INTO metrics(name,label,group_name,type,per80,weight,active) VALUES(?,?,?,?,?,?,1)", (key,label,grp,"count",int(per80),float(weight)))
                    st.success("Metric added"); st.rerun()
                except sqlite3.IntegrityError:
                    st.error("Key must be unique.")
    with st.expander("Edit / Toggle Active / Weights"):
        if not mdf.empty:
            mid=st.selectbox("Select metric", mdf["id"].tolist(), format_func=lambda x: mdf.loc[mdf["id"]==x,"label"].iloc[0])
            rec=mdf.loc[mdf["id"]==mid]
            col1,col2,col3,col4,col5=st.columns(5)
            with col1: new_label=st.text_input("Label", value=rec["label"].iloc[0])
            with col2: new_grp=st.selectbox("Group", ["Attack","Defense","Kicking","Discipline","Scoring","Other"], index=["Attack","Defense","Kicking","Discipline","Scoring","Other"].index(rec["group_name"].iloc[0]))
            with col3: new_per80=st.checkbox("Per-80", value=bool(rec["per80"].iloc[0]))
            with col4: new_active=st.checkbox("Active", value=bool(rec["active"].iloc[0]))
            with col5:
                base = rec["weight"].iloc[0] if pd.notna(rec["weight"].iloc[0]) else 0.0
                new_weight=st.number_input("Weight", value=float(base), step=0.5)
            if st.button("Save Metric Changes"):
                with conn: conn.execute("UPDATE metrics SET label=?, group_name=?, per80=?, active=?, weight=? WHERE id=?", (new_label,new_grp,int(new_per80),int(new_active),float(new_weight),mid))
                st.success("Saved"); st.rerun()

# ---------- Hotkeys ----------
def page_hotkeys(conn, role):
    gate(role, ("admin",))
    st.header("Hotkey Manager (WASD)")
    mdf=pd.read_sql_query("SELECT id,label,group_name FROM metrics WHERE active=1 ORDER BY group_name,label", conn)
    hmap=pd.read_sql_query("SELECT h.key, m.label, m.group_name FROM hotkeys h JOIN metrics m ON m.id=h.metric_id ORDER BY h.key", conn)
    st.subheader("Current Mapping"); st.dataframe(hmap, use_container_width=True)
    ALL_KEYS=[f"Key{c}" for c in list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")] + [f"Digit{d}" for d in "0123456789"]
    col1,col2=st.columns([1,2])
    with col1: key_choice=st.selectbox("Key", ALL_KEYS)
    with col2:
        choices=[(int(r["id"]), f'{r["label"]} ({r["group_name"]})') for r in mdf.to_dict("records")]
        label_by_id={int(r["id"]): r["label"] for r in mdf.to_dict("records")}
        metric_choice=st.selectbox("Metric", choices, format_func=lambda x: label_by_id.get(x[0]))
    if st.button("Save Mapping"):
        with conn: conn.execute("INSERT OR REPLACE INTO hotkeys(key, metric_id) VALUES(?,?)", (key_choice, int(metric_choice[0])))
        st.success("Saved"); st.rerun()
    if st.button("Load WASD Preset"):
        preset={"KeyW":"Tackles Made","KeyS":"Tackles Missed","KeyA":"Carries Made","KeyD":"Offloads","KeyQ":"Line Breaks","KeyE":"Assists","KeyR":"Tries","KeyF":"Turnovers Won","KeyG":"Turnovers Conceded","KeyV":"Handling Errors","KeyX":"Kick w/ Territory Gain","KeyC":"Kick w/o Territory Gain","KeyZ":"Penalties Conceded"}
        for k,label in preset.items():
            mid=_metric_id_by_label(conn, label)
            if mid:
                with conn: conn.execute("INSERT OR REPLACE INTO hotkeys(key, metric_id) VALUES(?,?)", (k, mid))
        st.success("WASD preset loaded"); st.rerun()
    if st.button("Clear All Hotkeys"):
        with conn: conn.execute("DELETE FROM hotkeys"); st.warning("Cleared"); st.rerun()

# ---------- Logger ----------
def page_logger(conn, role):
    st.header("Live Logger (Event → Player)")
    with st.expander("Create/Load Match"):
        opponent=st.text_input("Opponent")
        date=st.date_input("Date", value=dt.date.today())
        if st.button("Create/Use Match"):
            row=conn.execute("SELECT id FROM matches WHERE opponent=? AND date=?", (opponent, str(date))).fetchone()
            if row: mid=row["id"]
            else:
                with conn:
                    conn.execute("INSERT INTO matches(opponent,date) VALUES(?,?)",(opponent,str(date)))
                    mid=conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            st.session_state["match_id"]=mid; st.success(f"Match loaded: {opponent} — {date}"); st.rerun()
    mid=st.session_state.get("match_id")
    if not mid: st.info("Pick or create a match to start."); return
    players=pd.read_sql_query("SELECT id,name FROM players WHERE active=1 ORDER BY name", conn)
    if players.empty: st.warning("Add players first."); return
    current_player=st.selectbox("Current Player", players["id"].tolist(), format_func=lambda x: players.set_index("id")["name"].to_dict().get(x,"?"))
    metrics=pd.read_sql_query("SELECT id,label,group_name FROM metrics WHERE active=1 ORDER BY group_name,label", conn)
    for grp in metrics["group_name"].unique():
        st.subheader(grp)
        cols=st.columns(4)
        subset=metrics[metrics["group_name"]==grp]
        for i, (_,row) in enumerate(subset.iterrows()):
            if cols[i%4].button(row["label"], key=f"m_{int(row['id'])}"):
                with conn: conn.execute("INSERT INTO events(match_id,player_id,metric_id,value) VALUES(?,?,?,1)", (mid, int(current_player), int(row["id"])))
                st.toast(f"{row['label']} — logged for {players.set_index('id')['name'][int(current_player)]}", icon="✅")
    st.divider()
    st.subheader("Recent")
    recent=pd.read_sql_query("""
        SELECT e.id, p.name as player, m.label as metric, e.ts
        FROM events e JOIN players p ON p.id=e.player_id JOIN metrics m ON m.id=e.metric_id
        WHERE e.match_id=? ORDER BY e.id DESC LIMIT 30
    """, conn, params=(mid,))
    if not recent.empty: st.dataframe(recent, use_container_width=True)

# ---------- Dropbox ----------
def _dropbox_token():
    try: return st.secrets.get("DROPBOX_TOKEN")
    except Exception: return None

def _dropbox_upload(file_bytes: bytes, dest_path: str) -> str:
    token=_dropbox_token()
    if not token: raise RuntimeError("Missing DROPBOX_TOKEN in secrets")
    headers={
        "Authorization": f"Bearer {token}",
        "Dropbox-API-Arg": str({"path": dest_path, "mode": "overwrite", "mute": True}).replace("'","\\\""),
        "Content-Type": "application/octet-stream",
    }
    r=requests.post("https://content.dropboxapi.com/2/files/upload", headers=headers, data=file_bytes)
    r.raise_for_status()
    headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    data={"path": dest_path, "settings": {"requested_visibility": "public"}}
    r2=requests.post("https://api.dropboxapi.com/2/sharing/create_shared_link_with_settings", headers=headers, json=data)
    if r2.status_code==409:
        r2=requests.post("https://api.dropboxapi.com/2/sharing/list_shared_links", headers=headers, json={"path": dest_path, "direct_only": True})
    r2.raise_for_status()
    link=r2.json().get("url")
    if link and "?dl=0" in link: link=link.replace("?dl=0","?raw=1")
    elif link and "?dl=1" in link: link=link.replace("?dl=1","?raw=1")
    return link

# ---------- Video Review ----------
def page_video(conn, role):
    st.header("🎥 Video Review + Bookmarks + Speed")
    matches=pd.read_sql_query("SELECT id, opponent, date FROM matches ORDER BY date DESC", conn)
    if matches.empty:
        st.info("Create a match in the Logger first."); return
    opts=[(int(r["id"]), f"{r['date']} — {r['opponent']}") for r in matches.to_dict("records")]
    mid=st.selectbox("Match", opts, format_func=lambda x: dict(opts).get(x))

    vids=pd.read_sql_query("SELECT id,label,kind,url,offset FROM videos WHERE match_id=? ORDER BY id", conn, params=(int(mid),))
    with st.expander("Add video"):
        st.caption("Upload MP4/MOV. File will sync to Dropbox and a streamable link will be used for playback.")
        up=st.file_uploader("Upload video", type=["mp4","mov"], accept_multiple_files=False)
        label=st.text_input("Label", value="Main Feed")
        if st.button("Upload & Add"):
            if not up:
                st.error("Choose a file first")
            else:
                token=_dropbox_token()
                if not token:
                    st.error("Missing Dropbox token in secrets. Add DROPBOX_TOKEN and redeploy.")
                else:
                    data=up.read()
                    safe_label=label.replace("/","-")
                    dest=f"/rugbystats/match_{mid}/{safe_label}_{up.name}"
                    try:
                        url=_dropbox_upload(data, dest)
                        with conn: conn.execute("INSERT INTO videos(match_id,kind,url,label,offset) VALUES(?,?,?,?,0)", (int(mid),"mp4",url,label))
                        st.success("Uploaded & added video"); st.rerun()
                    except Exception as e:
                        st.error(f"Dropbox upload failed: {e}")

    if vids.empty:
        st.warning("No videos added yet."); return

    vopts=[(int(r["id"]), f"{r['label']} ({r['kind']})") for r in vids.to_dict("records")]
    vid=st.selectbox("Active video", vopts, format_func=lambda x: dict(vopts).get(x))
    vrow=conn.execute("SELECT id,url,offset FROM videos WHERE id=?", (int(vid),)).fetchone()
    off=st.number_input("Offset (sec)", value=float(vrow["offset"] or 0.0), step=1.0)
    if st.button("Save offset"):
        with conn: conn.execute("UPDATE videos SET offset=? WHERE id=?", (float(off), int(vid))); st.success("Saved"); st.rerun()

    rate=st.select_slider("Speed", options=[0.25,0.5,0.75,1.0,1.25,1.5,2.0], value=1.0)
    payload=video_hotkeys(url=vrow["url"], start=float(off), paused=False, rate=float(rate), key="vid")

    if payload:
        t=float(payload.get("t") or 0.0)
        if payload.get("type")=="bookmark":
            note=st.session_state.get("_note","") or ""
            with conn: conn.execute("INSERT INTO moments(match_id, video_id, video_ts, note) VALUES(?,?,?,?)", (int(mid), int(vid), t, note))
            st.toast(f"Bookmark @ {int(t)}s saved", icon="⭐")

    st.subheader("Bookmarks")
    st.session_state.setdefault("_note","")
    st.session_state["_note"]=st.text_input("Default note", value=st.session_state["_note"])
    bms=pd.read_sql_query("SELECT id, video_ts, note FROM moments WHERE match_id=? AND video_id=? ORDER BY video_ts", conn, params=(int(mid), int(vid)))
    if bms.empty: st.caption("Press Space to add a bookmark while playing.")
    else:
        for _, row in bms.iterrows():
            c1,c2,c3,c4=st.columns([1,5,1,1])
            with c1:
                tsec=float(row["video_ts"]); st.write(f"{int(tsec//60):02d}:{int(tsec%60):02d}")
            with c2:
                new_note=st.text_input("Note", value=row["note"], key=f"bm_{int(row['id'])}")
            with c3:
                if st.button("Save", key=f"save_{int(row['id'])}"):
                    with conn: conn.execute("UPDATE moments SET note=? WHERE id=?", (new_note, int(row["id"]))); st.success("Saved")
            with c4:
                if st.button("Jump ▶", key=f"jump_{int(row['id'])}"):
                    st.session_state["_seek_to"]=max(0.0, float(row["video_ts"])-3.0); st.rerun()
    if st.session_state.get("_seek_to") is not None:
        video_hotkeys(url=vrow["url"], start=float(off), paused=False, rate=float(rate), seek_to=float(st.session_state["_seek_to"]), key="vid")
        st.session_state["_seek_to"]=None

# ---------- Reports ----------
def page_reports(conn, role):
    st.header("Reports & Leaderboard")
    df=pd.read_sql_query("""
        SELECT p.name as player, m.label as metric, SUM(e.value) as total
        FROM events e JOIN players p ON p.id=e.player_id JOIN metrics m ON m.id=e.metric_id
        GROUP BY p.id, m.id ORDER BY p.name, m.label
    """, conn)
    if df.empty: st.info("No events yet."); return
    table=df.pivot(index="player", columns="metric", values="total").fillna(0).astype(int)
    st.subheader("Totals"); st.dataframe(table, use_container_width=True)
    w=pd.read_sql_query("SELECT label, weight FROM metrics WHERE active=1", conn)
    weights=dict(zip(w["label"], w["weight"].fillna(0.0)))
    w_series=pd.Series({col: float(weights.get(col,0.0)) for col in table.columns})
    score_df=table.mul(w_series, axis=1); score_df["Score"]=score_df.sum(axis=1)
    st.subheader("Leaderboard (Weighted)"); st.dataframe(score_df[["Score"]].sort_values("Score", ascending=False), use_container_width=True)

# ---------- Main ----------
def main():
    role=st.session_state.get("current_role","viewer")
    conn=get_conn()
    tabs=st.tabs(["Players","Metrics","Hotkeys","Live Logger","Reports","Video Review"])
    with tabs[0]: page_players(conn, role)
    with tabs[1]: page_metrics(conn, role)
    with tabs[2]: page_hotkeys(conn, role)
    with tabs[3]: page_logger(conn, role)
    with tabs[4]: page_reports(conn, role)
    with tabs[5]: page_video(conn, role)

if __name__=="__main__": main()
