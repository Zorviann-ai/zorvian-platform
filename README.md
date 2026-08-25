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
