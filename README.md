# helpdesk-lite

A small, self-contained support ticket system in a single Python file. Open a
ticket, work the queue, reply on a thread, and change priority or status —
through a plain web interface and a read-only JSON API. SQLite for storage, the
Python standard library for everything else.

## Why

Not every team needs a heavyweight help-desk product. `helpdesk-lite` is a
complete ticketing workflow you can run anywhere Python runs, with no database
server and no packages to install. It also doubles as a worked example of
**secure web coding** — the controls below are the point, not an afterthought.

## Features

- **Ticket queue** sorted so open and urgent work rises to the top.
- **Ticket detail** with a comment thread, status and priority controls.
- **Create / reply / update** via standard HTML forms.
- **JSON API** — `GET /api/tickets` and `GET /api/tickets/<id>` (with comments).
- **One file, one dependency-free binary's worth of code**, SQLite storage.

## Security controls (by design)

| Risk | Control |
| --- | --- |
| SQL injection | Every statement is parameterised — values are never string-formatted into SQL. |
| Stored XSS | Every dynamic value is `html.escape`d before it reaches the page. |
| CSRF | State changes are POST-only and require a per-session token matched against an `HttpOnly`, `SameSite=Strict` cookie. |
| Clickjacking / sniffing | `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` on every page. |
| Oversized / empty input | Server-side length and presence validation on every field. |
| Invalid enums | `status` and `priority` are checked against fixed allow-lists. |

## Requirements

Python 3.10 or newer. No packages to install.

## Usage

```bash
# Start the server (binds to localhost by default)
python3 helpdesk_lite.py --db helpdesk.db --port 8000
```

Open <http://127.0.0.1:8000/>.

### Options

| Flag | Description | Default |
| --- | --- | --- |
| `--db` | SQLite database file | `helpdesk.db` |
| `--host` | Bind address | `127.0.0.1` |
| `--port` | Port to listen on | `8000` |

### JSON API

```bash
# All tickets
curl http://127.0.0.1:8000/api/tickets

# One ticket with its comment thread
curl http://127.0.0.1:8000/api/tickets/1
```

## Data model

```
tickets(id, subject, body, requester, priority, status, created_at, updated_at)
comments(id, ticket_id → tickets.id, author, body, created_at)
```

`priority ∈ {low, normal, high, urgent}` · `status ∈ {open, in_progress,
resolved, closed}`.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The suite covers the store logic, the security controls (a real SQL-injection
payload is stored literally; a script payload comes back escaped), and the HTTP
routes end-to-end against a real server on an ephemeral port. Standard-library
`unittest`, no network access beyond loopback, no third-party dependencies.

## Scope

`helpdesk-lite` has no user accounts or authentication — it is meant for a
trusted internal network or as a teaching example of the secure-coding
controls above, not as a public, multi-tenant service. Put it behind
authentication and TLS before exposing it beyond localhost.

## License

MIT — see [LICENSE](LICENSE).
