# Local Inventory Runbook

This proof is local-only and requires no package installation or network access.

Run deterministic verification:

```sh
/usr/bin/python3 -B -m unittest discover -s tests -p 'test_*.py' -q
```

Run the application on loopback:

```sh
/usr/bin/python3 -B server.py --host 127.0.0.1 --port 8765 --db inventory.sqlite3
```

Open `http://127.0.0.1:8765/` in the governed browser. Inventory records are stored in the local
`inventory.sqlite3` database and persist across application restarts.
