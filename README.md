# Rail.Reserve — Backend

A real Flask + SQLite backend and database for Rail.Reserve. Same frontend
you've been using in the live preview — this just gives it a genuine server
and persistent database behind it, running on your own machine.

## Run it

```bash
pip install -r requirements.txt
python app.py
```

Then open **http://localhost:5000**.

Your data lives in `railreserve.db` (SQLite) in this folder. It survives
refreshes, logout/login, and restarting the server — it's a real database
file on disk, not browser storage. Delete that file to reset to a clean
install (just the one admin account, no other data).

## Configuration (environment variables)

Nothing sensitive is hardcoded in the source. Set these before running,
or put them in a `.env` file and load it however you prefer:

| Variable | Default | Purpose |
|---|---|---|
| `RAILRESERVE_SECRET` | a dev placeholder | Flask session signing key — set a real random value in production |
| `RAILRESERVE_ADMIN_EMAIL` | `admin@gmail.com` | The one admin account's email |
| `RAILRESERVE_ADMIN_PASSWORD` | `123456` | The one admin account's password |
| `RAZORPAY_KEY_ID` | *(unset)* | Your Razorpay Key ID (safe to expose to the frontend — Razorpay's own docs confirm this) |
| `RAZORPAY_KEY_SECRET` | *(unset)* | Your Razorpay Key Secret — **never sent to the frontend**, used only server-side to create orders and verify payment signatures |

Example:

```bash
export RAILRESERVE_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export RAILRESERVE_ADMIN_EMAIL="admin@yourcompany.com"
export RAILRESERVE_ADMIN_PASSWORD="a-real-password"
export RAZORPAY_KEY_ID="rzp_test_xxxxxxxxxxxx"
export RAZORPAY_KEY_SECRET="xxxxxxxxxxxxxxxxxxxxxxxx"
python app.py
```

There is exactly one admin account, created from these environment
variables at startup. There is no registration path that can create
another one — passenger self-registration only ever creates passenger
accounts.

## Payments

If `RAZORPAY_KEY_ID` and `RAZORPAY_KEY_SECRET` are both set, the app uses
**real Razorpay Checkout**:
- `POST /api/payments/create-order` creates a real Razorpay order
  server-side using your secret key (never exposed to the browser).
- The frontend opens Razorpay's own Checkout widget.
- `POST /api/payments/verify` verifies the payment signature server-side
  (HMAC-SHA256, exactly as Razorpay documents) before a booking is ever
  created. A booking is never created without a verified payment, and a
  given payment can never be used to create more than one booking.

Get free test-mode keys from your [Razorpay Dashboard](https://dashboard.razorpay.com/)
(Settings → API Keys → Generate Test Key) — no real charges occur in test
mode. Razorpay's documented test cards (e.g. `4111 1111 1111 1111`) work
in their Checkout widget.

If the keys are **not** set, the app still runs — the payment step falls
back to a clearly-labeled sandbox simulation (built into the frontend)
so you can test the full booking flow without a Razorpay account. That
fallback still enforces the same rule: a booking is only ever created
after a successful "payment."

## Demo login

| Role | Email | Password |
|---|---|---|
| Admin | value of `RAILRESERVE_ADMIN_EMAIL` (default `admin@gmail.com`) | value of `RAILRESERVE_ADMIN_PASSWORD` (default `123456`) |

Passengers create their own accounts from the login screen — there are no
seeded demo passengers, trains, routes, or stations. Everything starts
empty; add stations, then routes (built from those stations), then trains
(assigned to a route, with a real boarding date & time) from the admin
dashboard.

## What's real here

- **Single admin, backend-enforced** — checked in the login route itself,
  not just hidden in the UI. No code path can create a second admin.
- **Stations → Routes → Trains** — routes are built from real stations you
  create; trains are assigned to a route (which supplies their origin/
  destination); passenger search reads the same connected data.
- **Group bookings** — one passenger booking N seats gets one shared PNR
  across N booking rows.
- **Payment-gated bookings** — `POST /api/bookings/group` rejects any
  booking without a confirmed `PAID` status, and rejects a payment ID
  that's already been used (duplicate-payment protection).
- **Real persistence** — SQLite database file, survives refresh,
  logout/login, and restarting the server.
- **Dashboard stats & charts** — computed live from real rows; empty
  states when there's no data yet, not placeholder numbers.

## Notes

- This uses Flask's built-in dev server — fine for local use and testing.
  For a real deployment, put it behind a production WSGI server (gunicorn,
  etc.), serve over HTTPS, and set a real `RAILRESERVE_SECRET`.
- `razorpay` is in `requirements.txt`; if you don't need real payments you
  can skip configuring the two `RAZORPAY_*` variables and the app will run
  fine in sandbox-payment mode.
