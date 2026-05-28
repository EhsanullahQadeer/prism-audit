"""
tests/test_rbac_regression.py

RBAC scope isolation regression tests. Guards against endpoints that
bypass commission_scope_clause and fall back to singular-role branching.

Unit tests: scope helpers only, no DB required.
Integration tests: real SQL against seeded DB.

CI setup — add to .github/workflows/test.yml:

  jobs:
    rbac-regression:
      runs-on: ubuntu-latest
      services:
        postgres:
          image: postgres:16
          env:
            POSTGRES_USER: postgres
            POSTGRES_PASSWORD: postgres
            POSTGRES_DB: prism_audit_test
          ports: ["5432:5432"]
          options: >-
            --health-cmd pg_isready
            --health-interval 5s
            --health-retries 10
      env:
        PRISM_TEST_DATABASE_URL: postgresql://postgres:postgres@localhost:5432/prism_audit_test
        JWT_SECRET: ci-only-not-for-prod
        IKAPP_SYNC_TOKEN: dummy
        WIZIO_SYNC_TOKEN: dummy
      steps:
        - uses: actions/checkout@v4
        - uses: actions/setup-python@v5
          with: { python-version: "3.12" }
        - run: pip install -r requirements.txt pytest
        - run: pytest tests/test_rbac_regression.py -v

Add `rbac-regression` as a required status check in branch protection.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import pytest

from auth import (
    commission_scope_clause,
    client_scope_clause,
    entity_codes_for,
    has_role,
    is_admin,
)


# helpers

def _user(roles: list[dict]) -> dict:
    """Minimal user dict the auth helpers accept."""
    return {"id": 999, "username": "test_user", "roles": roles}


def _conseiller(code: str) -> dict:
    return _user([{"role": "conseiller", "entity_code": code,
                   "entity_fournisseur": None, "entity_produit": None}])


def _mentor(code: str) -> dict:
    return _user([{"role": "mentor", "entity_code": code,
                   "entity_fournisseur": None, "entity_produit": None}])


def _apporteur(code: str) -> dict:
    return _user([{"role": "apporteur", "entity_code": code,
                   "entity_fournisseur": None, "entity_produit": None}])


def _admin() -> dict:
    return _user([{"role": "admin", "entity_code": None,
                   "entity_fournisseur": None, "entity_produit": None}])


def _multi(roles: list[dict]) -> dict:
    return _user(roles)


class TestCommissionScope:

    def test_admin_gets_no_filter(self):
        clause, params = commission_scope_clause(_admin())
        assert clause == ""
        assert params == []

    def test_conseiller_filters_own_code(self):
        clause, params = commission_scope_clause(_conseiller("C01"))
        assert "code_conseiller = %s" in clause
        assert "C01" in params

    def test_conseiller_does_not_bleed_other_codes(self):
        clause, params = commission_scope_clause(_conseiller("C01"))
        assert "C02" not in params
        assert "C03" not in params

    def test_no_roles_is_deny_all(self):
        clause, params = commission_scope_clause(_user([]))
        assert clause == "1=0"
        assert params == []

    def test_apporteur_requires_retro_gt_zero(self):
        clause, params = commission_scope_clause(_apporteur("A01"))
        assert "montant_retrocession_apporteur" in clause
        assert "> 0" in clause
        assert "A01" in params

    def test_mentor_uses_subquery_not_direct_join(self):
        clause, params = commission_scope_clause(_mentor("M01"))
        assert "SELECT code FROM conseillers WHERE code_mentor" in clause
        assert "M01" in params

    def test_multi_role_produces_or_union(self):
        """Multi-role user must produce an OR-union clause covering all roles."""
        user = _multi([
            {"role": "conseiller", "entity_code": "C01",
             "entity_fournisseur": None, "entity_produit": None},
            {"role": "apporteur",  "entity_code": "A01",
             "entity_fournisseur": None, "entity_produit": None},
        ])
        clause, params = commission_scope_clause(user)
        assert " OR " in clause, (
            "Multi-role user must produce OR-union clause. "
            f"Got instead: {clause!r}\n"
            "If this fails, something is branching on singular role — "
            "that's the bug this guard exists to catch."
        )
        assert "C01" in params
        assert "A01" in params

    def test_alias_prefix_applied(self):
        clause, _ = commission_scope_clause(_conseiller("C01"), alias="comm")
        assert clause.startswith("(comm.")

    def test_partenaire_filters_by_fournisseur(self):
        user = _multi([{"role": "partenaire", "entity_code": None,
                        "entity_fournisseur": "AXA", "entity_produit": None}])
        clause, params = commission_scope_clause(user)
        assert "fournisseur = %s" in clause
        assert "AXA" in params


class TestClientScope:

    def test_admin_no_filter(self):
        clause, params = client_scope_clause(_admin())
        assert clause == ""

    def test_conseiller_scoped_to_code(self):
        clause, params = client_scope_clause(_conseiller("C01"), alias="c")
        assert "c.code_conseiller = %s" in clause
        assert "C01" in params

    def test_partenaire_denied_clients(self):
        # Partenaire has no client visibility by design.
        user = _multi([{"role": "partenaire", "entity_code": None,
                        "entity_fournisseur": "AXA", "entity_produit": None}])
        clause, params = client_scope_clause(user)
        assert clause == "1=0"

    def test_apporteur_uses_code_apporteur_column(self):
        clause, params = client_scope_clause(_apporteur("A01"), alias="c")
        assert "c.code_apporteur = %s" in clause
        assert "A01" in params

    def test_mentor_uses_subquery(self):
        clause, params = client_scope_clause(_mentor("M01"), alias="c")
        assert "SELECT code FROM conseillers WHERE code_mentor" in clause
        assert "M01" in params

    def test_multi_role_or_union(self):
        user = _multi([
            {"role": "conseiller", "entity_code": "C01",
             "entity_fournisseur": None, "entity_produit": None},
            {"role": "apporteur",  "entity_code": "A01",
             "entity_fournisseur": None, "entity_produit": None},
        ])
        clause, params = client_scope_clause(user, alias="c")
        assert " OR " in clause
        assert "C01" in params
        assert "A01" in params


# Integration tests — require conftest.py session fixtures (db_cursor, users).

class TestCommissionScopeIntegration:

    def test_alice_cannot_see_bob_commissions(self, db_cursor, users):
        """Alice (C01) must not see commissions with code_conseiller='C02'."""
        alice = users.get("alice")
        if alice is None:
            pytest.skip("seed user 'alice' not found — check seed.sql")

        clause, params = commission_scope_clause(alice)
        alice_codes = set(entity_codes_for(alice, "conseiller"))

        with db_cursor() as cur:
            q = "SELECT id, code_conseiller FROM commissions"
            if clause:
                q += f" WHERE {clause}"
            cur.execute(q, params)
            rows = cur.fetchall()

        leaked = [
            r for r in rows
            if r["code_conseiller"] not in alice_codes
            and r["code_conseiller"] is not None
        ]
        assert leaked == [], (
            f"RBAC leak: alice (codes={alice_codes}) can see commissions "
            f"from: {[(r['id'], r['code_conseiller']) for r in leaked]}"
        )

    def test_bob_cannot_see_alice_commissions(self, db_cursor, users):
        bob = users.get("bob")
        if bob is None:
            pytest.skip("seed user 'bob' not found")

        clause, params = commission_scope_clause(bob)
        bob_codes = set(entity_codes_for(bob, "conseiller"))

        with db_cursor() as cur:
            q = "SELECT id, code_conseiller FROM commissions"
            if clause:
                q += f" WHERE {clause}"
            cur.execute(q, params)
            rows = cur.fetchall()

        alice_only = [
            r for r in rows
            if r["code_conseiller"] == "C01"
            and "C01" not in bob_codes
        ]
        assert alice_only == [], (
            f"RBAC leak: bob can see alice's commissions: "
            f"{[r['id'] for r in alice_only]}"
        )

    def test_admin_sees_everything(self, db_cursor, users):
        admin = users.get("admin")
        if admin is None:
            pytest.skip("seed user 'admin' not found")

        clause, params = commission_scope_clause(admin)
        assert clause == "", "admin must get empty clause (no row filter)"

        with db_cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM commissions")
            total = cur.fetchone()["n"]

        assert total > 0, "seeded DB must contain commissions"

    def test_zero_roles_sees_nothing(self, db_cursor):
        no_roles = _user([])
        clause, params = commission_scope_clause(no_roles)
        assert clause == "1=0"

        with db_cursor() as cur:
            cur.execute(
                f"SELECT COUNT(*) AS n FROM commissions WHERE {clause}",
                params,
            )
            assert cur.fetchone()["n"] == 0


class TestClientScopeIntegration:

    def test_conseiller_only_sees_own_clients(self, db_cursor, users):
        alice = users.get("alice")
        if alice is None:
            pytest.skip("seed user 'alice' not found")

        clause, params = client_scope_clause(alice, alias="c")
        alice_codes = set(entity_codes_for(alice, "conseiller"))

        with db_cursor() as cur:
            q = "SELECT id, code_conseiller FROM clients c"
            if clause:
                q += f" WHERE {clause}"
            cur.execute(q, params)
            rows = cur.fetchall()

        leaked = [
            r for r in rows
            if r["code_conseiller"] not in alice_codes
            and r["code_conseiller"] is not None
        ]
        assert leaked == [], (
            f"RBAC leak: alice can see clients of: "
            f"{set(r['code_conseiller'] for r in leaked)}"
        )


@pytest.mark.parametrize("username,own_code,other_code", [
    ("alice", "C01", "C02"),
    ("bob",   "C02", "C01"),
])
def test_conseiller_isolation_parametric(
    db_cursor, users, username, own_code, other_code
):
    user = users.get(username)
    if user is None:
        pytest.skip(f"seed user '{username}' not found")

    clause, params = commission_scope_clause(user)

    with db_cursor() as cur:
        q = "SELECT id, code_conseiller FROM commissions"
        if clause:
            q += f" WHERE {clause}"
        cur.execute(q, params)
        rows = cur.fetchall()

    forbidden = [r for r in rows if r["code_conseiller"] == other_code]
    assert forbidden == [], (
        f"RBAC leak: '{username}' (scope={own_code}) can see "
        f"commissions with code_conseiller={other_code}: "
        f"ids={[r['id'] for r in forbidden]}"
    )
