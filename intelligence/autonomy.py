"""Tenant-safe autonomous Core control primitives.

The controller may perform reversible, internal CRM housekeeping automatically.
Consequential/external operations are never executed here; those cross the
provider mesh approval boundary in app_gate12.
"""
from dataclasses import dataclass
from typing import Any
import datetime
import uuid


DEFAULT_POLICY = {
    "mode": "supervised",
    "auto_create_followup_tasks": True,
    "max_actions_per_run": 12,
    "external_actions_require_approval": True,
}

ALLOWED_MODES = {"observe", "supervised", "active"}


@dataclass(frozen=True)
class CoreSnapshot:
    contacts: int
    open_tasks: int
    overdue_tasks: int
    bookings: int
    campaigns: int
    documents: int
    videos: int

    def as_dict(self) -> dict[str, int]:
        return {
            "contacts": self.contacts,
            "open_tasks": self.open_tasks,
            "overdue_tasks": self.overdue_tasks,
            "bookings": self.bookings,
            "campaigns": self.campaigns,
            "documents": self.documents,
            "videos": self.videos,
        }


def _iso_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def ensure_tables(connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS autonomy_settings(
            tenant_id TEXT PRIMARY KEY,
            mode TEXT NOT NULL DEFAULT 'supervised',
            auto_create_followup_tasks INTEGER NOT NULL DEFAULT 1,
            max_actions_per_run INTEGER NOT NULL DEFAULT 12,
            external_actions_require_approval INTEGER NOT NULL DEFAULT 1,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS autonomy_runs(
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            mode TEXT NOT NULL,
            trigger TEXT NOT NULL,
            snapshot_json TEXT NOT NULL,
            summary TEXT,
            actions_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS autonomy_actions(
            id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            action_type TEXT NOT NULL,
            target_id TEXT,
            detail TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )
    connection.commit()


def get_policy(connection, tenant_id: str) -> dict[str, Any]:
    ensure_tables(connection)
    row = connection.execute("SELECT * FROM autonomy_settings WHERE tenant_id=?", (tenant_id,)).fetchone()
    if not row:
        connection.execute(
            "INSERT INTO autonomy_settings VALUES (?,?,?,?,?,?)",
            (tenant_id, "supervised", 1, 12, 1, _iso_now()),
        )
        connection.commit()
        return dict(DEFAULT_POLICY)
    return {
        "mode": row["mode"],
        "auto_create_followup_tasks": bool(row["auto_create_followup_tasks"]),
        "max_actions_per_run": int(row["max_actions_per_run"]),
        "external_actions_require_approval": bool(row["external_actions_require_approval"]),
    }


def update_policy(connection, tenant_id: str, *, mode: str, auto_create_followup_tasks: bool,
                  max_actions_per_run: int, external_actions_require_approval: bool) -> dict[str, Any]:
    if mode not in ALLOWED_MODES:
        raise ValueError("Unknown autonomy mode")
    if max_actions_per_run < 1 or max_actions_per_run > 50:
        raise ValueError("max_actions_per_run must be between 1 and 50")
    ensure_tables(connection)
    connection.execute(
        """INSERT INTO autonomy_settings(tenant_id,mode,auto_create_followup_tasks,max_actions_per_run,external_actions_require_approval,updated_at)
           VALUES (?,?,?,?,?,?)
           ON CONFLICT(tenant_id) DO UPDATE SET mode=excluded.mode,
             auto_create_followup_tasks=excluded.auto_create_followup_tasks,
             max_actions_per_run=excluded.max_actions_per_run,
             external_actions_require_approval=excluded.external_actions_require_approval,
             updated_at=excluded.updated_at""",
        (tenant_id, mode, int(auto_create_followup_tasks), max_actions_per_run,
         int(external_actions_require_approval), _iso_now()),
    )
    connection.commit()
    return get_policy(connection, tenant_id)


def snapshot(connection, tenant_id: str) -> CoreSnapshot:
    def count(sql: str, args=(tenant_id,)) -> int:
        return int(connection.execute(sql, args).fetchone()[0])

    today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    return CoreSnapshot(
        contacts=count("SELECT COUNT(*) FROM contacts WHERE tenant_id=?"),
        open_tasks=count("SELECT COUNT(*) FROM tasks WHERE tenant_id=? AND COALESCE(status,'') NOT IN ('Done','Completed','Cancelled')"),
        overdue_tasks=count("SELECT COUNT(*) FROM tasks WHERE tenant_id=? AND due<>'' AND due<? AND COALESCE(status,'') NOT IN ('Done','Completed','Cancelled')", (tenant_id, today)),
        bookings=count("SELECT COUNT(*) FROM bookings WHERE tenant_id=?"),
        campaigns=count("SELECT COUNT(*) FROM campaigns WHERE tenant_id=?"),
        documents=count("SELECT COUNT(*) FROM documents WHERE tenant_id=?"),
        videos=count("SELECT COUNT(*) FROM video_projects WHERE tenant_id=?"),
    )


def create_safe_followups(connection, tenant_id: str, run_id: str, max_actions: int) -> list[dict[str, Any]]:
    """Create reversible internal follow-up tasks for contacts without an existing follow-up task."""
    contacts = connection.execute(
        "SELECT id,name,need,score FROM contacts WHERE tenant_id=? ORDER BY score DESC,created_at ASC LIMIT ?",
        (tenant_id, max_actions * 3),
    ).fetchall()
    actions: list[dict[str, Any]] = []
    for contact in contacts:
        if len(actions) >= max_actions:
            break
        marker = f"[contact:{contact['id']}]"
        exists = connection.execute(
            "SELECT id FROM tasks WHERE tenant_id=? AND title LIKE ? AND COALESCE(status,'') NOT IN ('Done','Completed','Cancelled') LIMIT 1",
            (tenant_id, f"%{marker}%"),
        ).fetchone()
        if exists:
            continue
        task_id = str(uuid.uuid4())
        title = f"Follow up {contact['name']} {marker}"
        if contact["need"]:
            title += f" - {str(contact['need'])[:120]}"
        now = _iso_now()
        connection.execute(
            "INSERT INTO tasks VALUES (?,?,?,?,?,?,?)",
            (task_id, tenant_id, title, "Zorvian Core", "", "Open", now),
        )
        action_id = str(uuid.uuid4())
        detail = f"Core created internal follow-up for contact {contact['name']} (score {contact['score'] or 0})."
        connection.execute(
            "INSERT INTO autonomy_actions VALUES (?,?,?,?,?,?,?,?)",
            (action_id, run_id, tenant_id, "task.create_followup", contact["id"], detail, "completed", now),
        )
        actions.append({"id": action_id, "type": "task.create_followup", "target_id": contact["id"], "task_id": task_id, "detail": detail})
    connection.commit()
    return actions
