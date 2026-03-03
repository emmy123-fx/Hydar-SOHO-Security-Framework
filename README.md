# SOHO Security Framework

Local network scanner web UI built with Flask.

Quick start

1. Create and activate a virtual environment (recommended):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate
```

2. Install dependencies:

```powershell
pip install -r requirements.txt
```

3. Note: `python-nmap` is a wrapper around the `nmap` binary. Install `nmap` for your OS (e.g., on Windows use the official installer).

4. Run the app:

```powershell
python app.py
```

5. Open the app in your browser at `http://127.0.0.1:5000/`.

Troubleshooting
- If you see HTTP 405 when submitting the form, ensure you are visiting the Flask URL (`http://127.0.0.1:5000/`) and not a static host/extension (e.g., Live Server at port 5500).
- Scanning may require elevated privileges; run with admin rights if needed.

License

This project is provided as-is for local testing and learning.
