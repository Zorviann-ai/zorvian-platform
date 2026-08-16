#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8787}"
COOKIE_A="$(mktemp)"
COOKIE_B="$(mktemp)"
trap 'rm -f "$COOKIE_A" "$COOKIE_B"' EXIT

json_assert() {
  local json="$1"
  shift
  echo "$json" | jq -e "$@" >/dev/null
}

status_request() {
  local out_file="$1"
  shift
  curl -sS -o "$out_file" -w '%{http_code}' "$@"
}

echo "Checking legacy health route"
health="$(curl -sS "$BASE_URL/api/health")"
json_assert "$health" '.ok == true and .service == "zorvian-platform"'

echo "Checking unauthenticated video API protection"
tmp="$(mktemp)"
code="$(status_request "$tmp" "$BASE_URL/api/video/providers")"
test "$code" = "401"
jq -e '.error == "unauthorized"' "$tmp" >/dev/null
rm -f "$tmp"

echo "Registering tenant A"
register_a="$(curl -sS -c "$COOKIE_A" -H 'content-type: application/json' \
  -d '{"name":"Phase One A","business":"Phase One Tenant A","email":"phase1-a@example.test","password":"phase-one-password-a"}' \
  "$BASE_URL/api/auth/register")"
json_assert "$register_a" '.ok == true'

me_a="$(curl -sS -b "$COOKIE_A" "$BASE_URL/api/me")"
json_assert "$me_a" '.authenticated == true and .tenant.name == "Phase One Tenant A"'

legacy_leads="$(curl -sS -b "$COOKIE_A" "$BASE_URL/api/leads")"
json_assert "$legacy_leads" '(.leads | type) == "array"'

echo "Creating and planning a video project"
create="$(curl -sS -b "$COOKIE_A" -H 'content-type: application/json' \
  -d '{"title":"Phase 1 Smoke Film","prompt":"Create a concise three-scene launch film for a fictional electric bicycle.","target_duration_seconds":15,"aspect_ratio":"16:9"}' \
  "$BASE_URL/api/video/projects")"
json_assert "$create" '.ok == true and .project.status == "planned" and (.project.scenes | length) > 0'
PROJECT_ID="$(echo "$create" | jq -r '.project.id')"
SCENE_COUNT="$(echo "$create" | jq -r '.project.scenes | length')"
test -n "$PROJECT_ID"

echo "Checking project persistence"
detail="$(curl -sS -b "$COOKIE_A" "$BASE_URL/api/video/projects/$PROJECT_ID")"
json_assert "$detail" --arg pid "$PROJECT_ID" '.ok == true and .project.id == $pid and (.project.scenes | length) > 0'

list="$(curl -sS -b "$COOKIE_A" "$BASE_URL/api/video/projects")"
json_assert "$list" --arg pid "$PROJECT_ID" 'any(.projects[]; .id == $pid)'

echo "Running zero-cost mock generation"
generated="$(curl -sS -b "$COOKIE_A" -X POST "$BASE_URL/api/video/projects/$PROJECT_ID/generate")"
json_assert "$generated" '.ok == true and .simulation == true and .project.status == "simulated"'
json_assert "$generated" '.project.costs.actual_micros == 0'
json_assert "$generated" '.project.renders[0].status == "simulated"'
json_assert "$generated" '[.project.scenes[].status] | all(. == "completed")'
json_assert "$generated" '[.project.jobs[].status] | all(. == "completed")'
json_assert "$generated" '[.project.jobs[].provider_key] | all(. == "mock")'
JOB_COUNT="$(echo "$generated" | jq -r '.project.jobs | length')"
test "$JOB_COUNT" = "$SCENE_COUNT"

echo "Verifying persisted completion state"
after="$(curl -sS -b "$COOKIE_A" "$BASE_URL/api/video/projects/$PROJECT_ID")"
json_assert "$after" '.project.status == "simulated" and .project.costs.actual_micros == 0'
json_assert "$after" '[.project.scenes[].output_asset_id] | all(. != null)'

list_after="$(curl -sS -b "$COOKIE_A" "$BASE_URL/api/video/projects")"
json_assert "$list_after" --arg pid "$PROJECT_ID" 'first(.projects[] | select(.id == $pid)) | .scene_count > 0 and .actual_cost_micros == 0'

echo "Registering tenant B and verifying tenant isolation"
register_b="$(curl -sS -c "$COOKIE_B" -H 'content-type: application/json' \
  -d '{"name":"Phase One B","business":"Phase One Tenant B","email":"phase1-b@example.test","password":"phase-one-password-b"}' \
  "$BASE_URL/api/auth/register")"
json_assert "$register_b" '.ok == true'

tmp="$(mktemp)"
code="$(status_request "$tmp" -b "$COOKIE_B" "$BASE_URL/api/video/projects/$PROJECT_ID")"
test "$code" = "404"
jq -e '.error == "video_project_not_found"' "$tmp" >/dev/null
rm -f "$tmp"

tmp="$(mktemp)"
code="$(status_request "$tmp" -b "$COOKIE_B" -X POST "$BASE_URL/api/video/projects/$PROJECT_ID/generate")"
test "$code" = "404"
jq -e '.error == "video_project_not_found"' "$tmp" >/dev/null
rm -f "$tmp"

list_b="$(curl -sS -b "$COOKIE_B" "$BASE_URL/api/video/projects")"
json_assert "$list_b" '.ok == true and (.projects | length) == 0'

echo "Checking /video workspace is served"
tmp="$(mktemp)"
code="$(status_request "$tmp" "$BASE_URL/video")"
test "$code" = "200"
grep -q '<title>Zorvian Video</title>' "$tmp"
rm -f "$tmp"

echo "Phase 1 smoke test passed"
