-- Phase 3 Stage 1 rollback.
-- Disables live functionality. Does NOT drop attempts, receipts, shadow runs,
-- confirmation records or audit evidence.

PRAGMA foreign_keys=ON;

UPDATE execution_live_grants SET enabled=0, updated_at=datetime('now');

INSERT INTO execution_kill_switches(id, scope, tenant_id, adapter_id, enabled, reason, updated_at)
SELECT lower(hex(randomblob(16))), 'global', NULL, NULL, 1, 'phase3_rollback_disablement', datetime('now')
WHERE NOT EXISTS (
  SELECT 1 FROM execution_kill_switches WHERE scope='global' AND enabled=1
);

INSERT INTO execution_phase3_audit(id, tenant_id, actor_id, event, subject_id, detail_json, created_at)
VALUES (
  lower(hex(randomblob(16))),
  'system',
  'system',
  'phase3_functionality_disabled',
  NULL,
  '{"reason":"rollback"}',
  datetime('now')
);
