"""Tests for helpdesk-lite: store logic, security controls, and HTTP routes."""
from __future__ import annotations

import http.client
import json
import os
import tempfile
import threading
import unittest

import helpdesk_lite
from helpdesk_lite import Store, ValidationError, e, serve


class StoreTicketTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")

    def tearDown(self):
        self.store.close()

    def test_create_and_get(self):
        tid = self.store.create_ticket("Printer down", "It won't print",
                                       "Sara", "high")
        ticket = self.store.get_ticket(tid)
        self.assertEqual(ticket["subject"], "Printer down")
        self.assertEqual(ticket["priority"], "high")
        self.assertEqual(ticket["status"], "open")

    def test_empty_subject_rejected(self):
        with self.assertRaises(ValidationError):
            self.store.create_ticket("", "body", "Sara")

    def test_oversized_subject_rejected(self):
        with self.assertRaises(ValidationError):
            self.store.create_ticket("x" * 200, "body", "Sara")

    def test_bad_priority_rejected(self):
        with self.assertRaises(ValidationError):
            self.store.create_ticket("s", "b", "Sara", "catastrophic")

    def test_list_orders_open_urgent_first(self):
        low = self.store.create_ticket("low", "b", "a", "low")
        self.store.update_ticket(low, status="closed")
        self.store.create_ticket("urgent", "b", "a", "urgent")
        tickets = self.store.list_tickets()
        self.assertEqual(tickets[0]["subject"], "urgent")

    def test_list_filter_by_status(self):
        self.store.create_ticket("a", "b", "x")
        tid = self.store.create_ticket("c", "d", "y")
        self.store.update_ticket(tid, status="closed")
        closed = self.store.list_tickets("closed")
        self.assertEqual(len(closed), 1)
        self.assertEqual(closed[0]["subject"], "c")

    def test_invalid_status_filter_raises(self):
        with self.assertRaises(ValidationError):
            self.store.list_tickets("nonsense")

    def test_update_status_and_priority(self):
        tid = self.store.create_ticket("a", "b", "x")
        self.assertTrue(self.store.update_ticket(tid, status="resolved",
                                                 priority="low"))
        ticket = self.store.get_ticket(tid)
        self.assertEqual(ticket["status"], "resolved")
        self.assertEqual(ticket["priority"], "low")

    def test_update_bad_status_raises(self):
        tid = self.store.create_ticket("a", "b", "x")
        with self.assertRaises(ValidationError):
            self.store.update_ticket(tid, status="banana")

    def test_update_nothing_returns_false(self):
        tid = self.store.create_ticket("a", "b", "x")
        self.assertFalse(self.store.update_ticket(tid))

    def test_counts_by_status(self):
        self.store.create_ticket("a", "b", "x")
        tid = self.store.create_ticket("c", "d", "y")
        self.store.update_ticket(tid, status="closed")
        counts = self.store.counts_by_status()
        self.assertEqual(counts.get("open"), 1)
        self.assertEqual(counts.get("closed"), 1)


class StoreCommentTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.tid = self.store.create_ticket("subj", "body", "Sara")

    def tearDown(self):
        self.store.close()

    def test_add_and_list(self):
        self.store.add_comment(self.tid, "Agent", "Looking into it")
        comments = self.store.list_comments(self.tid)
        self.assertEqual(len(comments), 1)
        self.assertEqual(comments[0]["author"], "Agent")

    def test_comment_on_missing_ticket_rejected(self):
        with self.assertRaises(ValidationError):
            self.store.add_comment(9999, "Agent", "hi")

    def test_empty_comment_rejected(self):
        with self.assertRaises(ValidationError):
            self.store.add_comment(self.tid, "Agent", "")

    def test_comment_bumps_ticket_updated_at(self):
        before = self.store.get_ticket(self.tid)["updated_at"]
        self.store.add_comment(self.tid, "Agent", "reply")
        after = self.store.get_ticket(self.tid)["updated_at"]
        self.assertGreaterEqual(after, before)


class SecurityTests(unittest.TestCase):
    """SQL injection and XSS are defused by parameterisation and escaping."""

    def setUp(self):
        self.store = Store(":memory:")

    def tearDown(self):
        self.store.close()

    def test_sql_injection_is_stored_literally(self):
        payload = "Robert'); DROP TABLE tickets;--"
        tid = self.store.create_ticket(payload, "body", "x")
        # The table still exists and the value round-trips verbatim.
        self.assertEqual(self.store.get_ticket(tid)["subject"], payload)
        self.assertEqual(len(self.store.list_tickets()), 1)

    def test_escape_neutralises_script(self):
        escaped = e("<script>alert(1)</script>")
        self.assertNotIn("<script>", escaped)
        self.assertIn("&lt;script&gt;", escaped)

    def test_escape_quotes(self):
        self.assertIn("&quot;", e('a "quoted" value'))


class HttpServerTests(unittest.TestCase):
    """End-to-end tests against a real server on an ephemeral port."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.store = Store(self.db_path)
        self.httpd = serve(self.store, "127.0.0.1", 0)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       args=(0.01,), daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        self.store.close()
        os.remove(self.db_path)

    def _conn(self):
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)

    def _get(self, path, headers=None):
        conn = self._conn()
        conn.request("GET", path, headers=headers or {})
        resp = conn.getresponse()
        body = resp.read().decode("utf-8")
        resp_headers = dict(resp.getheaders())
        conn.close()
        return resp.status, body, resp_headers

    def _post(self, path, data, headers=None):
        conn = self._conn()
        body = "&".join(f"{k}={v}" for k, v in data.items())
        base = {"Content-Type": "application/x-www-form-urlencoded"}
        base.update(headers or {})
        conn.request("POST", path, body=body, headers=base)
        resp = conn.getresponse()
        resp.read()
        resp_headers = dict(resp.getheaders())
        conn.close()
        return resp.status, resp_headers

    def _session(self):
        """GET the index and return a usable (csrf_token, cookie_header)."""
        _status, body, headers = self._get("/")
        cookie = headers.get("Set-Cookie", "").split(";")[0]
        token = cookie.split("=", 1)[1]
        return token, cookie

    def test_index_sets_csrf_cookie_and_csp(self):
        status, _body, headers = self._get("/")
        self.assertEqual(status, 200)
        self.assertIn("csrf=", headers.get("Set-Cookie", ""))
        self.assertIn("default-src 'self'", headers.get(
            "Content-Security-Policy", ""))

    def test_post_without_csrf_is_forbidden(self):
        status, _headers = self._post(
            "/tickets", {"subject": "x", "body": "y", "requester": "z",
                         "priority": "normal"})
        self.assertEqual(status, 403)

    def test_create_ticket_with_csrf(self):
        token, cookie = self._session()
        status, headers = self._post(
            "/tickets",
            {"subject": "Login+broken", "body": "cannot+log+in",
             "requester": "Sara", "priority": "high", "csrf": token},
            headers={"Cookie": cookie})
        self.assertEqual(status, 303)
        self.assertTrue(headers.get("Location", "").startswith("/ticket/"))

    def test_api_tickets_json(self):
        token, cookie = self._session()
        self._post("/tickets",
                   {"subject": "API+test", "body": "b", "requester": "r",
                    "priority": "normal", "csrf": token},
                   headers={"Cookie": cookie})
        status, body, _headers = self._get("/api/tickets")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data[0]["subject"], "API test")

    def test_api_single_ticket_includes_comments(self):
        token, cookie = self._session()
        self._post("/tickets",
                   {"subject": "s", "body": "b", "requester": "r",
                    "priority": "normal", "csrf": token},
                   headers={"Cookie": cookie})
        status, body, _headers = self._get("/api/tickets/1")
        self.assertEqual(status, 200)
        self.assertIn("comments", json.loads(body))

    def test_api_missing_ticket_404(self):
        status, _body, _headers = self._get("/api/tickets/9999")
        self.assertEqual(status, 404)

    def test_stored_xss_payload_is_escaped_in_html(self):
        token, cookie = self._session()
        self._post("/tickets",
                   {"subject": "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
                    "body": "b", "requester": "r", "priority": "normal",
                    "csrf": token},
                   headers={"Cookie": cookie})
        _status, body, _headers = self._get("/ticket/1")
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertIn("&lt;script&gt;", body)

    def test_add_comment_via_http(self):
        token, cookie = self._session()
        self._post("/tickets",
                   {"subject": "s", "body": "b", "requester": "r",
                    "priority": "normal", "csrf": token},
                   headers={"Cookie": cookie})
        status, headers = self._post(
            "/ticket/1/comment",
            {"author": "Agent", "body": "on+it", "csrf": token},
            headers={"Cookie": cookie})
        self.assertEqual(status, 303)
        _s, body, _h = self._get("/ticket/1")
        self.assertIn("on it", body)

    def test_update_via_http(self):
        token, cookie = self._session()
        self._post("/tickets",
                   {"subject": "s", "body": "b", "requester": "r",
                    "priority": "normal", "csrf": token},
                   headers={"Cookie": cookie})
        status, _headers = self._post(
            "/ticket/1/update",
            {"status": "resolved", "priority": "low", "csrf": token},
            headers={"Cookie": cookie})
        self.assertEqual(status, 303)
        _s, body, _h = self._get("/api/tickets/1")
        self.assertEqual(json.loads(body)["status"], "resolved")

    def test_invalid_ticket_data_returns_400(self):
        token, cookie = self._session()
        status, _headers = self._post(
            "/tickets",
            {"subject": "", "body": "b", "requester": "r",
             "priority": "normal", "csrf": token},
            headers={"Cookie": cookie})
        self.assertEqual(status, 400)

    def test_ticket_html_not_found(self):
        status, body, _headers = self._get("/ticket/9999")
        self.assertEqual(status, 404)
        self.assertIn("not found", body.lower())

    def test_unknown_path_404(self):
        status, _body, _headers = self._get("/nope")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
