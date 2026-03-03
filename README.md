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

## Features

* User authentication (login/logout) with password hashing
* Network discovery and port/service scanning
* Rule-based vulnerability detection
* Risk scoring and simple dashboard
* SQLite database storage of scans and users
* Bootstrap/Chart.js UI

## Database

On first run the SQLite database `soho.db` is created automatically. A
default admin user is not generated automatically; you can create one using a
Python snippet:

```python
from database.models import initialize, get_connection
from modules.auth import hash_password
initialize()
conn = get_connection()
cur = conn.cursor()
cur.execute('INSERT OR IGNORE INTO users (username,password_hash) VALUES (?,?)',
			('admin', hash_password('password')))
conn.commit(); conn.close()
```

## Testing

Unit tests for the core detection logic live in `tests/test_core.py` and can be
run with:

```bash
python -m unittest discover tests
```

## Next Steps

You can extend the framework by adding /modules for real CVE lookups, export
PDF reports, schedule periodic scans, or deploy behind a WSGI server like
gunicorn.


License

This project is provided as-is for local testing and learning.
