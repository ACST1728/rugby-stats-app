import os
import streamlit as st
import streamlit.components.v1 as components

_build_dir = os.path.join(os.path.dirname(__file__), "components", "video_hotkeys")
_video_hotkeys = components.declare_component("video_hotkeys", path=_build_dir)

def video_hotkeys(url: str, start: float = 0.0, paused: bool = False, rate: float = 1.0, seek_to: float | None = None, key: str | None = None):
    return _video_hotkeys(url=url, start=float(start or 0), paused=bool(paused), rate=float(rate or 1.0), seek_to=seek_to, key=key)
