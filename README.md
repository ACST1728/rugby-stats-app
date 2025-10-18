# Rugby Stats v3y — Deploy via GitHub → Streamlit Cloud

This repository contains your ready-to-run rugby stats app with:
- Streamlit entrypoint (`streamlit_app.py`)
- Main app (`rugby_stats_app_v3y.py`)
- Pinned requirements (`requirements.txt`)
- Optional CI sanity check (`.github/workflows/ci.yml`)

---

## 🚀 Quick Deploy (Streamlit Community Cloud)

1. **Create a new GitHub repo** (empty).
2. **Upload these files**:
   - `rugby_stats_app_v3y.py`
   - `streamlit_app.py`
   - `requirements.txt`
   - `README.md`
   - (optional) `.github/workflows/ci.yml`
3. Go to **https://share.streamlit.io** and sign in with GitHub.
4. Click **New app** → select your repo and branch.
5. Set **Main file path** to: `streamlit_app.py`
6. Click **Deploy**.

> First build takes a few minutes while dependencies install.

---

## 🔐 Secrets (Dropbox token etc.)

If you plan to use cloud backups to Dropbox:

1. In Streamlit Cloud: **App → Settings → Secrets**.
2. Add your token like this:
   ```
   DROPBOX_ACCESS_TOKEN = "sl.BCxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
   ```
3. Save secrets. In the app, go to **Settings → Cloud Backup** and click **Backup now** to test.

> Do **not** commit secrets to Git — keep them in Streamlit Secrets.

---

## 🛠 Local run (optional)

```bash
pip install -r requirements.txt
python -m streamlit run streamlit_app.py
```

---

## ✅ CI (optional but recommended)

This repo includes a minimal GitHub Actions workflow that checks:
- Dependencies install
- The app module imports without syntax errors

Enable by committing `.github/workflows/ci.yml`.

---

## 📂 Files

- `streamlit_app.py` — small launcher that imports and runs `rugby_stats_app_v3y.main()`
- `rugby_stats_app_v3y.py` — the actual app
- `requirements.txt` — Python packages required
- `.github/workflows/ci.yml` — optional automation
- `README.md` — this guide

---

## 🧰 Troubleshooting

- **Module not found** during deploy → add to `requirements.txt`, commit & push.
- **Wrong entrypoint** → confirm “Main file path” is `streamlit_app.py`.
- **Viewer/admin accounts** → manage in **Settings → User Management** inside the app.
- **Excel export** → ensure `xlsxwriter` is present (already in requirements).
- **Dropbox** → token must be set in **Secrets** (see above).

Need help? Open an issue in your repo, or ping me with the exact error message.
