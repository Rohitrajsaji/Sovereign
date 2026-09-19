from __future__ import annotations

import argparse
import html
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


class InventoryStore:
    def __init__(self, database: str) -> None:
        self.connection = sqlite3.connect(database)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS inventory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                quantity INTEGER NOT NULL CHECK(quantity > 0)
            )
            """
        )
        self.connection.commit()

    @staticmethod
    def validate(name: str, quantity_text: str) -> tuple[str, int]:
        normalized = name.strip()
        if not normalized:
            raise ValueError("name_required")
        try:
            quantity = int(quantity_text)
        except ValueError as error:
            raise ValueError("quantity_integer_required") from error
        if quantity <= 0:
            raise ValueError("quantity_must_be_positive")
        return normalized, quantity

    def create(self, name: str, quantity_text: str) -> int:
        normalized, quantity = self.validate(name, quantity_text)
        cursor = self.connection.execute(
            "INSERT INTO inventory(name, quantity) VALUES(?, ?)",
            (normalized, quantity),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def update(self, item_id: int, name: str, quantity_text: str) -> None:
        normalized, quantity = self.validate(name, quantity_text)
        cursor = self.connection.execute(
            "UPDATE inventory SET name = ?, quantity = ? WHERE id = ?",
            (normalized, quantity, item_id),
        )
        if cursor.rowcount != 1:
            raise ValueError("item_not_found")
        self.connection.commit()

    def delete(self, item_id: int) -> None:
        cursor = self.connection.execute("DELETE FROM inventory WHERE id = ?", (item_id,))
        if cursor.rowcount != 1:
            raise ValueError("item_not_found")
        self.connection.commit()

    def search(self, query: str) -> list[sqlite3.Row]:
        if not query:
            return list(self.connection.execute("SELECT id, name, quantity FROM inventory ORDER BY id"))
        return list(
            self.connection.execute(
                "SELECT id, name, quantity FROM inventory WHERE name LIKE ? ORDER BY id",
                (f"%{query}%",),
            )
        )

    def close(self) -> None:
        self.connection.close()


def render_page(template_root: Path, store: InventoryStore, query: str = "", error: str = "") -> bytes:
    template = (template_root / "web" / "index.html").read_text(encoding="utf-8")
    rows = []
    for item in store.search(query):
        item_id = int(item["id"])
        name = html.escape(str(item["name"]))
        quantity = int(item["quantity"])
        rows.append(
            f"""
            <li data-item-id="{item_id}">
              <strong>{name}</strong> <span>quantity={quantity}</span>
              <form id="edit-{item_id}" method="post" action="/edit">
                <input type="hidden" name="id" value="{item_id}">
                <input name="name" value="Widget Pro">
                <input name="quantity" value="5">
                <button type="submit">Edit</button>
              </form>
              <form id="delete-{item_id}" method="post" action="/delete">
                <input type="hidden" name="id" value="{item_id}">
                <button type="submit">Delete</button>
              </form>
            </li>
            """
        )
    rendered = (
        template.replace("{{ROWS}}", "\n".join(rows) or "<li>No inventory items</li>")
        .replace("{{QUERY}}", html.escape(query))
        .replace("{{ERROR}}", html.escape(error))
    )
    return rendered.encode("utf-8")


def render_read_only_page(store: InventoryStore, query: str = "", error: str = "") -> bytes:
    rows = []
    for item in store.search(query):
        rows.append(
            f"<li><strong>{html.escape(str(item['name']))}</strong> "
            f"<span>quantity={int(item['quantity'])}</span></li>"
        )
    rendered_rows = "\n".join(rows) or "<li>No inventory items</li>"
    return f"""<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>Sovereign Inventory View</title></head>
  <body>
    <main>
      <h1>Inventory</h1>
      <p id="validation">{html.escape(error)}</p>
      <p>Search query: {html.escape(query)}</p>
      <ul id="inventory-items">{rendered_rows}</ul>
    </main>
  </body>
</html>""".encode("utf-8")


class InventoryHandler(BaseHTTPRequestHandler):
    server_version = "SovereignInventory/1"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._write(200, b"ok", "text/plain; charset=utf-8")
            return
        if parsed.path not in {"/", "/view"}:
            self._write(404, b"not found", "text/plain; charset=utf-8")
            return
        query = parse_qs(parsed.query).get("q", [""])[0]
        if parsed.path == "/view":
            self._write(200, render_read_only_page(self.server.store, query))
        else:
            self._write(200, render_page(self.server.template_root, self.server.store, query))

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        form = parse_qs(self.rfile.read(length).decode("utf-8"), keep_blank_values=True)
        try:
            if self.path == "/create":
                self.server.store.create(form.get("name", [""])[0], form.get("quantity", [""])[0])
            elif self.path == "/edit":
                self.server.store.update(
                    int(form.get("id", ["0"])[0]),
                    form.get("name", [""])[0],
                    form.get("quantity", [""])[0],
                )
            elif self.path == "/delete":
                self.server.store.delete(int(form.get("id", ["0"])[0]))
            else:
                self._write(404, b"not found", "text/plain; charset=utf-8")
                return
        except (ValueError, TypeError) as error:
            body = render_read_only_page(
                self.server.store,
                error=f"Validation error: {error}",
            )
            self._write(400, body)
            return
        self.send_response(303)
        self.send_header("Location", "/")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return

    def _write(self, status: int, body: bytes, content_type: str = "text/html; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class InventoryServer(HTTPServer):
    def __init__(self, address: tuple[str, int], template_root: Path, database: str) -> None:
        self.template_root = template_root
        self.store = InventoryStore(database)
        super().__init__(address, InventoryHandler)

    def server_close(self) -> None:
        self.store.close()
        super().server_close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--db", default="inventory.sqlite3")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    server = InventoryServer((args.host, args.port), root, args.db)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
