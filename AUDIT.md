# PRISM — Audit Report
**Files reviewed:** `backend/auth.py`, `backend/routers/commissions.py`, `backend/routers/clients.py`, `backend/schemas.py`, `backend/helpers.py`, `db/schema.sql`
**By:** Ehsanullah Qadeer
**Date:** 2026-05-25

---

## Quick take

`commission_scope_clause`, `client_scope_clause`, the OR-union logic, and token revocation are correctly implemented in `auth.py`. Two endpoints bypass these helpers and fall back to singular `current_user["role"]` branching — that is the primary exposure. `reassign_conseiller` has a race condition under concurrent writes. Remaining findings are lower priority.

10 findings below. 3 high, 4 medium, 2 low, 1 dead-code cleanup.

---

## Finding 1 — HIGH
**File:** `backend/routers/commissions.py` ~line 140–240 (`export_commissions`)

The export endpoint builds its SQL WHERE clause by branching on `role = current_user["role"]` — the singular primary role. For a user with both `[conseiller, apporteur]` roles, `role` resolves to `"conseiller"` (higher priority), and the apporteur branch never runs. Two consequences:

1. Their export silently drops apporteur-scoped commissions that should be included.
2. The column restrictions bypass fires incorrectly — the apporteur role is supposed to receive a reduced column set that excludes `montant_commission_ia` and internal split figures. Instead they get the full conseiller layout, including financial data they have no right to see.

This is the anti-pattern your own codebase documents and prohibits. The list endpoint (`list_commissions`) already does this correctly with `commission_scope_clause`. The export just never got the same treatment.

**Fix:** Replace the entire `if role == "conseiller" / elif role == "mentor" / elif role == "apporteur"` block in the WHERE-building section with `commission_scope_clause(current_user, alias="c")`. For column masking, use `has_role(current_user, "apporteur") and not has_role(current_user, "conseiller", "mentor")` — same logic as `_mask_admin_only`.

---

## Finding 2 — HIGH
**File:** `backend/routers/clients.py` ~line 370–390 (`list_clients`, `nb_subq`)

The `nb_commissions` subquery attached to each client row branches on `current_user.get("role")` (singular). The main WHERE clause uses `client_scope_clause` correctly — so the right clients come back. But the commission count on each client is computed with the wrong scope.

For a `[mentor, apporteur]` user: `role = "mentor"`, so the apporteur retro-count branch is silently skipped. The apporteur ends up seeing commission counts that include rows outside their retro scope — data the apporteur role is not supposed to see.

**Fix:** Build `nb_subq` by injecting `commission_scope_clause(current_user)` into the subquery instead of branching on singular role. The apporteur `retro > 0` restriction should use `has_role()` not `role ==`.

---

## Finding 3 — HIGH
**File:** `backend/routers/clients.py` ~line 525–530 (`reassign_conseiller`)

The entire reassign operation — read old state, UPDATE clients, UPDATE commissions, recompute retros — runs in one `db_cursor(commit=True)` block, but there is no row-level lock on the client row before the reads.

Two admins hitting `reassign-conseiller` on the same `client_id` at the same time: both read `old_code` as identical, both run `UPDATE clients`, both run `UPDATE commissions`. The second transaction blindly commits over the first. No conflict error, no log, no trace of the collision. In reventilation mode this can leave commissions split across two conseillers with no way to detect it after the fact.

**Fix:** Change the client fetch at step 1 from a plain SELECT to:
```sql
SELECT ... FROM clients WHERE id = %s FOR UPDATE
```
One line. PostgreSQL will serialize concurrent transactions on the same client row — the second admin blocks until the first commits, then reads the already-updated state and gets a clean "already assigned to X" error.

---

## Finding 4 — MEDIUM
**File:** `backend/routers/commissions.py` ~line 60–80 (`_commission_filter`)

Dead function that branches on `current_user["role"]` (singular). The comment even says "Currently unused — dead code." It's not live risk today, but it's a copy-paste trap. Next developer looking for a filter helper will find this, use it, and ship the bug. The migration to multi-role helpers is implicitly incomplete as long as this exists.

**Fix:** Delete it. No replacement needed — `commission_scope_clause` already exists for this purpose.

---

## Finding 5 — MEDIUM
**File:** `backend/routers/commissions.py` ~line 110–120 (`list_commissions`, partenaire guard)

The partenaire redirect guard reads `role == "partenaire"`. A user with `[partenaire, apporteur]` has `role = "apporteur"` (higher priority) — they skip the 403 guard entirely. `commission_scope_clause` still handles their data correctly (no row leak), but the redirect to `/api/partenaires/commissions` is silently bypassed. Their column visibility and the UX intent for partenaire data is broken.

**Fix:** `has_role(current_user, "partenaire") and not has_role(current_user, "conseiller", "mentor", "apporteur", "admin")` — only redirect pure-partenaire users.

---

## Finding 6 — MEDIUM
**File:** `backend/routers/commissions.py` ~line 312 (`create_commission`) and ~line 393 (`update_commission`)

Both endpoints wrap the `recompute_for_conseiller_year` call in `except Exception: pass`. If the IA engine recompute fails for any reason — DB error, import issue, logic bug — the commission is committed with stale tier calculations and nothing is logged. Financially incorrect data silently in production, no way to detect it without manually cross-checking advisor payout figures.

The intent to not block the main operation is right. The silence is not.

**Fix:**
```python
except Exception as e:
    logger.warning("recompute_for_conseiller_year failed for %s/%s: %s",
                   code_conseiller, year, e, exc_info=True)
```
One line. Keeps the non-blocking behaviour, makes the failure observable.

---

## Finding 7 — MEDIUM
**File:** `backend/routers/clients.py` ~line 613 (`reassign_conseiller`, reventilation loop)

Same `except Exception: pass` pattern around `recompute_for_conseiller_year` inside the reventilation loop. Higher stakes than Finding 6 — this is the moment a commission changes hands. If the IA recompute silently fails here, the new advisor's annual tier is wrong from the moment of assignment. The audit trail row commits fine, so it looks clean in `client_interactions`, but the financial state is inconsistent.

**Fix:** Same as Finding 6 — log at WARNING, don't swallow.

---

## Finding 8 — MEDIUM
**File:** `backend/routers/clients.py` ~line 575–595 (`reassign_conseiller`, reventilation step 2)

In the retro-recompute loop, `c.get("code_conseiller")` is pulled from the RETURNING clause of the commission UPDATE — which returns the *new* value already written to DB. So `impacted_pairs` only ever collects the new conseiller for IA recompute. The old conseiller is never added. Their annual CA stays inflated with commissions that just got reassigned away from them.

`update_client` (line ~560 in clients.py) already handles this correctly — it explicitly adds `old_code_cons` to `impacted_pairs` after the loop. `reassign_conseiller` doesn't.

**Fix:** Before the commission UPDATE, the old code is already in scope as `old_code`. After building `impacted_pairs` in the loop, add:
```python
for c in affected:
    if c.get("year"):
        impacted_pairs.add((old_code, int(c["year"])))
```

---

## Finding 9 — LOW
**File:** `backend/helpers.py` lines 12–13

```python
IKAPP_SYNC_TOKEN = os.environ["IKAPP_SYNC_TOKEN"]
WIZIO_SYNC_TOKEN = os.environ["WIZIO_SYNC_TOKEN"]
```

These raise `KeyError` on import if the env vars are missing. The app crashes at boot before FastAPI can return anything useful. Compare with `auth.py` which does this right — `os.getenv()` then an explicit `RuntimeError` with a message that tells you exactly which variable to set.

**Fix:** Same pattern as `JWT_SECRET` in `auth.py`:
```python
_ikapp = os.getenv("IKAPP_SYNC_TOKEN")
if not _ikapp:
    raise RuntimeError("IKAPP_SYNC_TOKEN is not set")
IKAPP_SYNC_TOKEN = _ikapp
```

---

## Finding 10 — LOW
**File:** `backend/routers/clients.py` ~line 200–210 (`search_clients`)

When `client_scope_clause` returns `"1=0"` (user has no client scope — e.g. a pure partenaire), the function doesn't short-circuit. It appends `1=0` and runs the full trigram similarity query against the clients table anyway. Every autocomplete keystroke fires a DB round-trip guaranteed to return nothing. Not a security issue — just wasted work on every keystroke.

`list_commissions` already has the early-return guard for this case. `search_clients` missed it.

**Fix:**
```python
scope_sql, scope_params = client_scope_clause(current_user, alias="")
if scope_sql == "1=0":
    return []
```

---

## What's clean

Worth noting so the picture is balanced:

- `commission_scope_clause` and `client_scope_clause` — OR-union logic is correct across all five roles including the mentor subquery. No issues.
- `get_commission` / `get_client` single-object fetches — both use `user_can_access_commission` / `user_can_access_client`, which are multi-role aware. No issues.
- `reassign_conseiller` audit trail — `client_interactions` row always written, motif enforced, JSON payload comprehensive. Well done.
- MFA enforcement patch (`PATCH_C_MFA_ENFORCEMENT_2026_05_16`) — correct and necessary.
- Token revocation via `token_blocklist` with opportunistic expiry cleanup — clean pattern.
