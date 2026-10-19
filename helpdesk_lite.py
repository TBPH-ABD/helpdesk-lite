#!/usr/bin/env python3
"""helpdesk-lite - a small, self-contained support ticket system.

A help desk in one file: open a ticket, list the queue, read a ticket with its
comment thread, add a reply, and change priority or status. It serves a plain
HTML interface and a read-only JSON API, stores everything in SQLite, and runs
on the Python standard library alone.

It is written to demonstrate secure web coding: every SQL statement is
parameterised, every value rendered into HTML is escaped, state-changing
requests are limited to POST and carry a per-session CSRF token, inputs are
length-validated, and a strict Content-Security-Policy is sent with every page.

    python3 helpdesk_lite.py --db helpdesk.db --port 8000

Then open http://127.0.0.1:8000/. It binds to localhost by default.
"""
from __future__ import annotations

import argparse
import html
import http.cookies
import json
import secrets
import sqlite3
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PRIORITIES = ("low", "normal", "high", "urgent")
STATUSES = ("open", "in_progress", "resolved", "closed")

_MAX_SUBJECT = 150
_MAX_BODY = 5000
_MAX_AUTHOR = 80

SCHEMA = """
CREATE TABLE IF NOT EXISTS tickets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    subject     TEXT NOT NULL,
    body        TEXT NOT NULL,
    requester   TEXT NOT NULL,
    priority    TEXT NOT NULL DEFAULT 'normal',
    status      TEXT NOT NULL DEFAULT 'open',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS comments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id   INTEGER NOT NULL REFERENCES tickets(id),
    author      TEXT NOT NULL,
    body        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_comments_ticket ON comments(ticket_id);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ValidationError(ValueError):
    """Raised when submitted ticket data does not pass validation."""


class Store:
    """All database access. Every query here is parameterised."""

    def __init__(self, path: str):
        # check_same_thread=False: the ThreadingHTTPServer serves each request
        # on its own thread. Writes are serialised by SQLite's own locking.
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # -- validation -------------------------------------------------------

    @staticmethod
    def _clean(value: str, *, field: str, maxlen: int,
               required: bool = True) -> str:
        value = (value or "").strip()
        if required and not value:
            raise ValidationError(f"{field} is required")
        if len(value) > maxlen:
            raise ValidationError(
                f"{field} must be at most {maxlen} characters")
        return value

    # -- tickets ----------------------------------------------------------

    def create_ticket(self, subject: str, body: str, requester: str,
                       priority: str = "normal") -> int:
        subject = self._clean(subject, field="subject", maxlen=_MAX_SUBJECT)
        body = self._clean(body, field="description", maxlen=_MAX_BODY)
        requester = self._clean(requester, field="requester",
                                maxlen=_MAX_AUTHOR)
        if priority not in PRIORITIES:
            raise ValidationError(f"priority must be one of {PRIORITIES}")
        now = _now()
        cursor = self.conn.execute(
            "INSERT INTO tickets "
            "(subject, body, requester, priority, status, created_at, "
            "updated_at) VALUES (?, ?, ?, ?, 'open', ?, ?)",
            (subject, body, requester, priority, now, now))
        self.conn.commit()
        return cursor.lastrowid

    def list_tickets(self, status: str | None = None) -> list[sqlite3.Row]:
        if status is not None and status not in STATUSES:
            raise ValidationError(f"status must be one of {STATUSES}")
        # Sort open/urgent work to the top: by status order, then priority.
        order = ("ORDER BY CASE status WHEN 'open' THEN 0 "
                 "WHEN 'in_progress' THEN 1 WHEN 'resolved' THEN 2 ELSE 3 END,"
                 " CASE priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 "
                 "WHEN 'normal' THEN 2 ELSE 3 END, updated_at DESC")
        if status:
            return self.conn.execute(
                f"SELECT * FROM tickets WHERE status = ? {order}",
                (status,)).fetchall()
        return self.conn.execute(f"SELECT * FROM tickets {order}").fetchall()

    def get_ticket(self, ticket_id: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()

    def update_ticket(self, ticket_id: int, *, status: str | None = None,
                      priority: str | None = None) -> bool:
        if status is not None and status not in STATUSES:
            raise ValidationError(f"status must be one of {STATUSES}")
        if priority is not None and priority not in PRIORITIES:
            raise ValidationError(f"priority must be one of {PRIORITIES}")
        sets, params = [], []
        if status is not None:
            sets.append("status = ?")
            params.append(status)
        if priority is not None:
            sets.append("priority = ?")
            params.append(priority)
        if not sets:
            return False
        sets.append("updated_at = ?")
        params.append(_now())
        params.append(ticket_id)
        cursor = self.conn.execute(
            f"UPDATE tickets SET {', '.join(sets)} WHERE id = ?", params)
        self.conn.commit()
        return cursor.rowcount > 0

    # -- comments ---------------------------------------------------------

    def add_comment(self, ticket_id: int, author: str, body: str) -> int:
        if self.get_ticket(ticket_id) is None:
            raise ValidationError("ticket does not exist")
        author = self._clean(author, field="author", maxlen=_MAX_AUTHOR)
        body = self._clean(body, field="comment", maxlen=_MAX_BODY)
        cursor = self.conn.execute(
            "INSERT INTO comments (ticket_id, author, body, created_at) "
            "VALUES (?, ?, ?, ?)", (ticket_id, author, body, _now()))
        self.conn.execute(
            "UPDATE tickets SET updated_at = ? WHERE id = ?",
            (_now(), ticket_id))
        self.conn.commit()
        return cursor.lastrowid

    def list_comments(self, ticket_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM comments WHERE ticket_id = ? ORDER BY created_at",
            (ticket_id,)).fetchall()

    def counts_by_status(self) -> dict:
        rows = self.conn.execute(
            "SELECT status, COUNT(*) AS n FROM tickets GROUP BY status"
        ).fetchall()
        return {row["status"]: row["n"] for row in rows}


# ----------------------------------------------------------------------------
# HTML rendering (every dynamic value passes through html.escape)
# ----------------------------------------------------------------------------

def e(value) -> str:
    return html.escape(str(value), quote=True)


_BADGE = {"urgent": "#b91c1c", "high": "#c2410c", "normal": "#1d4ed8",
          "low": "#6b7280", "open": "#1d4ed8", "in_progress": "#c2410c",
          "resolved": "#15803d", "closed": "#6b7280"}


def _page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)} - helpdesk-lite</title>
<style>
 body {{ font-family: system-ui, sans-serif; max-width: 860px; margin: 2rem auto;
        padding: 0 1rem; color: #1f2933; line-height: 1.5; }}
 a {{ color: #1d4ed8; text-decoration: none; }}
 h1 {{ font-size: 1.4rem; }}
 table {{ width: 100%; border-collapse: collapse; }}
 th, td {{ text-align: left; padding: .5rem; border-bottom: 1px solid #e5e7eb; }}
 .badge {{ color: #fff; border-radius: 10px; padding: 0 .5rem; font-size: .8rem; }}
 form.card, .card {{ border: 1px solid #e5e7eb; border-radius: 8px;
                     padding: 1rem; margin: 1rem 0; }}
 label {{ display: block; margin: .5rem 0 .2rem; font-weight: 600; }}
 input, textarea, select {{ width: 100%; padding: .4rem; box-sizing: border-box;
                            border: 1px solid #cbd5e1; border-radius: 6px; }}
 button {{ margin-top: .6rem; padding: .5rem 1rem; border: 0; border-radius: 6px;
          background: #1d4ed8; color: #fff; cursor: pointer; }}
 .comment {{ border-left: 3px solid #e5e7eb; padding-left: .8rem; margin: .8rem 0; }}
 .meta {{ color: #6b7280; font-size: .85rem; }}
</style>
</head>
<body>
<p><a href="/">&larr; helpdesk-lite</a></p>
{body}
</body>
</html>"""


def badge(value: str) -> str:
    colour = _BADGE.get(value, "#6b7280")
    return f'<span class="badge" style="background:{colour}">{e(value)}</span>'


def render_index(tickets, counts, csrf: str) -> str:
    summary = " &middot; ".join(
        f"{e(status)}: {counts.get(status, 0)}" for status in STATUSES)
    rows = "".join(
        f"<tr><td><a href='/ticket/{t['id']}'>#{t['id']}</a></td>"
        f"<td><a href='/ticket/{t['id']}'>{e(t['subject'])}</a></td>"
        f"<td>{badge(t['priority'])}</td><td>{badge(t['status'])}</td>"
        f"<td>{e(t['requester'])}</td><td class='meta'>{e(t['updated_at'])}</td>"
        f"</tr>" for t in tickets)
    if not rows:
        rows = "<tr><td colspan='6' class='meta'>No tickets yet.</td></tr>"
    priority_options = "".join(
        f"<option value='{p}'{' selected' if p == 'normal' else ''}>{p}"
        f"</option>" for p in PRIORITIES)
    body = f"""
<h1>Support queue</h1>
<p class="meta">{summary}</p>
<table>
<tr><th>#</th><th>Subject</th><th>Priority</th><th>Status</th>
    <th>Requester</th><th>Updated</th></tr>
{rows}
</table>

<form class="card" method="post" action="/tickets">
 <h2>Open a ticket</h2>
 <input type="hidden" name="csrf" value="{e(csrf)}">
 <label for="requester">Your name</label>
 <input id="requester" name="requester" maxlength="{_MAX_AUTHOR}" required>
 <label for="subject">Subject</label>
 <input id="subject" name="subject" maxlength="{_MAX_SUBJECT}" required>
 <label for="priority">Priority</label>
 <select id="priority" name="priority">{priority_options}</select>
 <label for="body">Description</label>
 <textarea id="body" name="body" rows="4" maxlength="{_MAX_BODY}" required></textarea>
 <button type="submit">Create ticket</button>
</form>
"""
    return _page("Support queue", body)


def render_ticket(ticket, comments, csrf: str) -> str:
    comment_html = "".join(
        f"<div class='comment'><div>{e(c['body'])}</div>"
        f"<div class='meta'>{e(c['author'])} &middot; {e(c['created_at'])}</div>"
        f"</div>" for c in comments)
    if not comment_html:
        comment_html = "<p class='meta'>No replies yet.</p>"
    status_options = "".join(
        f"<option value='{s}'{' selected' if s == ticket['status'] else ''}>"
        f"{s}</option>" for s in STATUSES)
    priority_options = "".join(
        f"<option value='{p}'{' selected' if p == ticket['priority'] else ''}>"
        f"{p}</option>" for p in PRIORITIES)
    body = f"""
<h1>#{ticket['id']}: {e(ticket['subject'])}</h1>
<p>{badge(ticket['priority'])} {badge(ticket['status'])}
   <span class="meta">opened by {e(ticket['requester'])} on
   {e(ticket['created_at'])}</span></p>
<div class="card">{e(ticket['body'])}</div>

<form class="card" method="post" action="/ticket/{ticket['id']}/update">
 <h2>Update</h2>
 <input type="hidden" name="csrf" value="{e(csrf)}">
 <label for="status">Status</label>
 <select id="status" name="status">{status_options}</select>
 <label for="priority">Priority</label>
 <select id="priority" name="priority">{priority_options}</select>
 <button type="submit">Save</button>
</form>

<h2>Replies</h2>
{comment_html}

<form class="card" method="post" action="/ticket/{ticket['id']}/comment">
 <input type="hidden" name="csrf" value="{e(csrf)}">
 <label for="author">Your name</label>
 <input id="author" name="author" maxlength="{_MAX_AUTHOR}" required>
 <label for="cbody">Reply</label>
 <textarea id="cbody" name="body" rows="3" maxlength="{_MAX_BODY}" required></textarea>
 <button type="submit">Add reply</button>
</form>
"""
    return _page(f"Ticket #{ticket['id']}", body)


# ----------------------------------------------------------------------------
# HTTP handler
# ----------------------------------------------------------------------------

def make_handler(store: Store):
    """Build a request-handler class bound to a given store."""

    class Handler(BaseHTTPRequestHandler):
        server_version = "helpdesk-lite"
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # keep the console quiet
            pass

        # -- helpers ------------------------------------------------------

        def _session_csrf(self) -> tuple[str, str | None]:
            """Return (csrf_token, set_cookie_value_or_None)."""
            cookie = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
            if "csrf" in cookie and cookie["csrf"].value:
                return cookie["csrf"].value, None
            token = secrets.token_urlsafe(32)
            return token, token

        def _send_html(self, body: str, status: int = 200,
                       set_csrf: str | None = None) -> None:
            payload = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; style-src 'unsafe-inline'; "
                             "base-uri 'none'; form-action 'self'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            if set_csrf is not None:
                morsel = http.cookies.SimpleCookie()
                morsel["csrf"] = set_csrf
                morsel["csrf"]["httponly"] = True
                morsel["csrf"]["samesite"] = "Strict"
                morsel["csrf"]["path"] = "/"
                self.send_header("Set-Cookie",
                                 morsel["csrf"].OutputString())
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)

        def _send_json(self, obj, status: int = 200) -> None:
            payload = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)

        def _redirect(self, location: str) -> None:
            self.send_response(303)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _read_form(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length).decode("utf-8") if length else ""
            parsed = urllib.parse.parse_qs(raw, keep_blank_values=True)
            return {k: v[0] for k, v in parsed.items()}

        def _check_csrf(self, form: dict) -> bool:
            cookie = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
            token = cookie["csrf"].value if "csrf" in cookie else None
            submitted = form.get("csrf", "")
            return bool(token) and secrets.compare_digest(token, submitted)

        # -- routing ------------------------------------------------------

        def do_GET(self):
            route = urllib.parse.urlparse(self.path)
            parts = [p for p in route.path.split("/") if p]
            query = urllib.parse.parse_qs(route.query)

            if not parts:
                csrf, set_csrf = self._session_csrf()
                status_filter = query.get("status", [None])[0]
                try:
                    tickets = store.list_tickets(status_filter)
                except ValidationError:
                    tickets = store.list_tickets()
                self._send_html(
                    render_index(tickets, store.counts_by_status(), csrf),
                    set_csrf=set_csrf)
                return

            if parts == ["api", "tickets"]:
                self._send_json([dict(t) for t in store.list_tickets()])
                return

            if len(parts) == 3 and parts[:2] == ["api", "tickets"] \
                    and parts[2].isdigit():
                ticket = store.get_ticket(int(parts[2]))
                if ticket is None:
                    self._send_json({"error": "not found"}, status=404)
                    return
                payload = dict(ticket)
                payload["comments"] = [dict(c) for c in
                                       store.list_comments(ticket["id"])]
                self._send_json(payload)
                return

            if len(parts) == 2 and parts[0] == "ticket" and parts[1].isdigit():
                ticket = store.get_ticket(int(parts[1]))
                if ticket is None:
                    self._send_html(_page("Not found",
                                          "<h1>Ticket not found</h1>"),
                                    status=404)
                    return
                csrf, set_csrf = self._session_csrf()
                self._send_html(
                    render_ticket(ticket,
                                  store.list_comments(ticket["id"]), csrf),
                    set_csrf=set_csrf)
                return

            self._send_html(_page("Not found", "<h1>Not found</h1>"),
                            status=404)

        def do_HEAD(self):
            self.do_GET()

        def do_POST(self):
            route = urllib.parse.urlparse(self.path)
            parts = [p for p in route.path.split("/") if p]
            form = self._read_form()

            if not self._check_csrf(form):
                self._send_html(_page("Forbidden",
                                      "<h1>403 - invalid CSRF token</h1>"
                                      "<p><a href='/'>Reload</a> and retry.</p>"),
                                status=403)
                return

            try:
                if parts == ["tickets"]:
                    ticket_id = store.create_ticket(
                        form.get("subject", ""), form.get("body", ""),
                        form.get("requester", ""),
                        form.get("priority", "normal"))
                    self._redirect(f"/ticket/{ticket_id}")
                    return

                if len(parts) == 3 and parts[0] == "ticket" \
                        and parts[1].isdigit() and parts[2] == "comment":
                    store.add_comment(int(parts[1]), form.get("author", ""),
                                      form.get("body", ""))
                    self._redirect(f"/ticket/{parts[1]}")
                    return

                if len(parts) == 3 and parts[0] == "ticket" \
                        and parts[1].isdigit() and parts[2] == "update":
                    store.update_ticket(
                        int(parts[1]),
                        status=form.get("status") or None,
                        priority=form.get("priority") or None)
                    self._redirect(f"/ticket/{parts[1]}")
                    return
            except ValidationError as exc:
                self._send_html(_page("Error",
                                      f"<h1>Could not save</h1><p>{e(exc)}</p>"
                                      "<p><a href='/'>Back</a></p>"),
                                status=400)
                return

            self._send_html(_page("Not found", "<h1>Not found</h1>"),
                            status=404)

    return Handler


def serve(store: Store, host: str, port: int) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, port), make_handler(store))
    return httpd


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="helpdesk-lite",
        description="A small self-contained support ticket system "
                    "(HTML + JSON API, SQLite, standard library only).")
    parser.add_argument("--db", default="helpdesk.db",
                        help="SQLite database file (default: helpdesk.db)")
    parser.add_argument("--host", default="127.0.0.1",
                        help="bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000,
                        help="port to listen on (default: 8000)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    store = Store(args.db)
    httpd = serve(store, args.host, args.port)
    print(f"helpdesk-lite on http://{args.host}:{args.port}/  (db: {args.db})")
    print("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        httpd.server_close()
        store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
