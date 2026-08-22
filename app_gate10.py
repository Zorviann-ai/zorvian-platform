"""Gate 7 tenant mailbox auto-provisioning layer.

Ensures existing and future workspaces receive a deterministic inbound mailbox
mapping when the global Resend inbound provider is configured. This closes the
gap where older tenants could receive mail at <slug>@domain in Resend but Core
had no mailbox_settings row to route that message to.
"""
import json
import uuid

import app as core_app
import app_gate9

app = app_gate9.app


def _provision_missing_mailboxes():
    outbound, inbound = app_gate9._mailbox_capabilities()
    domain = app_gate9._inbound_domain()
    if not inbound or not domain:
        return

    status = "connected" if outbound and inbound else ("outbound_only" if outbound else "not_connected")
    c = core_app.db()
    tenants = c.execute("SELECT id,name,slug FROM tenants").fetchall()
    changed = []

    for tenant in tenants:
        tenant_id = tenant["id"]
        display = tenant["name"] or "Zorvian Client"
        alias = app_gate9._safe_alias(tenant["slug"] or tenant_id[:10])
        address = f"{alias}@{domain}"
        row = c.execute("SELECT tenant_id,inbound_address,status FROM mailbox_settings WHERE tenant_id=?", (tenant_id,)).fetchone()

        if row:
            if row["inbound_address"] != address or row["status"] != status:
                c.execute(
                    "UPDATE mailbox_settings SET display_name=?,inbound_address=?,status=?,updated_at=? WHERE tenant_id=?",
                    (display, address, status, core_app.now(), tenant_id),
                )
                changed.append((tenant_id, address))
        else:
            c.execute(
                "INSERT INTO mailbox_settings VALUES (?,?,?,?,?,?)",
                (tenant_id, display, address, status, core_app.now(), core_app.now()),
            )
            changed.append((tenant_id, address))

        config = json.dumps({"inbound_address": address, "professional_html": True, "tenant_routing": True})
        integration = c.execute("SELECT id FROM integrations WHERE tenant_id=? AND provider='email'", (tenant_id,)).fetchone()
        if integration:
            c.execute("UPDATE integrations SET status=?,config_json=? WHERE id=?", (status, config, integration["id"]))
        else:
            c.execute(
                "INSERT INTO integrations VALUES (?,?,?,?,?,?)",
                (str(uuid.uuid4()), tenant_id, "email", status, config, core_app.now()),
            )

    for tenant_id, address in changed:
        c.execute(
            "INSERT INTO audit VALUES (?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), tenant_id, None, "mailbox_auto_provisioned", f"inbound={address}; status={status}", "info", core_app.now()),
        )
    c.commit()
    c.close()


@app.middleware("http")
async def gate7_mailbox_provisioning(request, call_next):
    # Auto-provision only on routes where discovery/routing needs it.
    # Do not run this pass before /mailbox/send (or other normal mailbox actions):
    # an unrelated provisioning/database issue must never block an authenticated
    # workspace from sending mail through its already-configured mailbox.
    path = request.url.path
    if path.startswith("/webhooks/resend") or path in {"/mailbox/status", "/mailbox/activate", "/integrations"}:
        _provision_missing_mailboxes()
    return await call_next(request)
