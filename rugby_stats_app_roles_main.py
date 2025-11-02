import os, sqlite3, datetime as dt
import pandas as pd
import streamlit as st
import altair as alt

DB_FILE = os.environ.get("RUGBY_DB_PATH", os.path.join(".", "rugby_stats.db"))
SCHEMA = """PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS players(
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    position TEXT,
    active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS matches(
    id INTEGER PRIMARY KEY,
    opponent TEXT NOT NULL,
    date TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS metrics(
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    label TEXT NOT NULL,
    group_name TEXT NOT NULL,
    per80 INTEGER NOT NULL DEFAULT 1,
    weight REAL,
    active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS events(
    id INTEGER PRIMARY KEY,
    match_id INTEGER NOT NULL,
    player_id INTEGER NOT NULL,
    metric_id INTEGER NOT NULL,
    value REAL NOT NULL DEFAULT 1,
    ts TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

def get_conn():
    dp=os.path.dirname(DB_FILE)
    if dp and dp not in ("/",""):
        try: os.makedirs(dp, exist_ok=True)
        except PermissionError: pass
    c=sqlite3.connect(DB_FILE, check_same_thread=False)
    c.row_factory=sqlite3.Row
    with c: c.executescript(SCHEMA)
    return c

def main():
    st.title("Rugby Stats — Roles Demo")
    role=st.session_state.get("current_role","viewer")
    conn=get_conn()

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
                pid=st.selectbox("Player", df["id"].tolist(), format_func=lambda x: df.loc[df["id"]==x,"name"].iloc[0])
                col1,col2,col3=st.columns(3)
                with col1: new_name=st.text_input("Name", value=df.loc[df["id"]==pid,"name"].iloc[0])
                with col2: new_pos=st.text_input("Position", value=df.loc[df["id"]==pid,"position"].iloc[0] or "")
                with col3: new_active=st.checkbox("Active", value=bool(df.loc[df["id"]==pid,"active"].iloc[0]))
                if st.button("Save changes"):
                    with conn: conn.execute("UPDATE players SET name=?, position=?, active=? WHERE id=?", (new_name,new_pos,int(new_active),pid))
                    st.success("Saved"); st.rerun()
    else:
        st.info("Read‑only: login as admin/editor to edit players.")

    st.divider()
    st.header("Reports (readable by all)")
    if not df.empty:
        c = alt.Chart(df).mark_bar().encode(x="name:N", y=alt.value(1), tooltip=["name","position"])
        st.altair_chart(c, use_container_width=True)

if __name__=="__main__": main()
