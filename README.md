# Caelomere Core Backend — Next Stage

Working local API backend with:
- SQLite database
- Tenant-aware records
- Login/session tokens
- Role-aware permissions
- CRM
- Receptionist routing into CRM + tasks
- Bookings into confirmation tasks
- Documents
- Campaigns
- Maps/route workflow records
- Freight/fleet jobs
- Video production plans
- Audit log / Guardian foundation
- Integration registry

Run:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

Open `http://127.0.0.1:8000/docs`.

Demo login:
- admin@zorvian.local
- zorvian-demo

External telephony, SMS, email, live social publishing, live maps/traffic, payments,
travel, vehicle data and video rendering remain gated until real provider accounts,
credentials and commercial permissions are connected.


## Brand and legal identity

- Product brand: **Caelomere**
- Registered company: **Caelomere Ltd**
- Primary website: **https://caelomere.com**
- `caelomere.co.uk` may be used as a redirect or domain alias.

Legacy internal identifiers such as database names, Worker names and session-cookie names remain unchanged during the rebrand so existing deployments and user sessions are not broken.

## Public contact addresses

- General enquiries: **hello@caelomere.com**
- Customer support: **support@caelomere.com**

Authentication, password reset, billing and other security-sensitive messages should use separately controlled transactional sender addresses rather than either public inbox.
