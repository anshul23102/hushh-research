"""
Regression proof for the structural PII leak described in issue #586.

This test proves that a "poisoned" LLM output — where sensitive dollar
amounts are embedded into JSON key names instead of values — is fully
detected and scrubbed by the SummaryReducerAgent post-processing guardrail.

Run with: pytest tests/agents/test_prove_dollar_leak.py -s
"""

from hushh_mcp.agents.summary_reducer.agent import SummaryReducerAgent


def test_dollar_leak_via_key_names_is_caught():
    """
    Simulate the exact attack vector: LLM encodes account balance into
    a presence-flag key name to bypass value-level scrubbing.

    Before the fix: the poisoned payload passed through as valid because
    the boolean values were clean.

    After the fix: the guardrail detects and strips the unsafe keys.
    """
    agent = SummaryReducerAgent()

    # Poisoned output simulating a misbehaving LLM (issue #586 PoC)
    poisoned_llm_output = {
        "presence_flags": {
            "account_$50000": True,  # balance hidden in key name
            "has_holdings_data": True,  # "holdings" in key name
            "has_basic_info": True,  # safe — should survive
        },
        "counts": {
            "total_logins": 5,  # safe
        },
        "freshness_markers": {},
        "sanctioned_capability_flags": [
            "view_$1000",  # dollar amount in capability string
            "can_trade",  # safe — should survive
        ],
    }

    clean = agent.sanitise_llm_output(poisoned_llm_output)

    print("\n--- AFTER GUARDRAILS: THE SANITISED PROJECTION ---")
    print(f"Presence Flags : {clean.presence_flags}")
    print(f"Counts         : {clean.counts}")
    print(f"Capabilities   : {clean.sanctioned_capability_flags}")

    # Unsafe keys must be gone
    assert "account_$50000" not in clean.presence_flags, (
        "FAIL: dollar amount in key name was not stripped"
    )
    assert "has_holdings_data" not in clean.presence_flags, (
        "FAIL: 'holdings' in key name was not stripped"
    )
    assert "view_$1000" not in clean.sanctioned_capability_flags, (
        "FAIL: dollar amount in capability string was not stripped"
    )

    # Safe data must remain
    assert clean.presence_flags.get("has_basic_info") is True, (
        "FAIL: safe presence flag was incorrectly stripped"
    )
    assert clean.counts.get("total_logins") == 5, "FAIL: safe count was incorrectly stripped"
    assert "can_trade" in clean.sanctioned_capability_flags, (
        "FAIL: safe capability was incorrectly stripped"
    )

    print("\n[SUCCESS] Guardrail detected PII in structural keys and stripped them.")
    print("Only safe data survived:")
    print(f"  Presence Flags : {clean.presence_flags}")
    print(f"  Counts         : {clean.counts}")
    print(f"  Capabilities   : {clean.sanctioned_capability_flags}")


def test_pre_processing_blindfold_works():
    """
    Prove that pre-processing blindfolds the LLM to raw sensitive values
    before they ever reach the LLM context.
    """
    agent = SummaryReducerAgent()

    raw_pkm_data = {
        "financial": {
            "balance": 50000,  # sensitive
            "holdings": [  # sensitive
                {"symbol": "AAPL", "value": 10000},
            ],
            "account_number": "1234-5678",  # sensitive
            "last_login": "2026-05-01",  # not sensitive
        },
        "has_trades": True,  # not sensitive
    }

    blindfolded = agent.pre_process(raw_pkm_data)

    print("\n--- AFTER PRE-PROCESSING: THE BLINDFOLDED DATA ---")
    print(f"financial.balance      : {blindfolded['financial']['balance']}")
    print(f"financial.holdings     : {blindfolded['financial']['holdings']}")
    print(f"financial.account_num  : {blindfolded['financial']['account_number']}")
    print(f"financial.last_login   : {blindfolded['financial']['last_login']}")
    print(f"has_trades             : {blindfolded['has_trades']}")

    assert blindfolded["financial"]["balance"] == "[REDACTED FOR REDUCER]"
    assert blindfolded["financial"]["holdings"] == "[REDACTED FOR REDUCER]"
    assert blindfolded["financial"]["account_number"] == "[REDACTED FOR REDUCER]"
    # Non-sensitive values pass through unchanged
    assert blindfolded["financial"]["last_login"] == "2026-05-01"
    assert blindfolded["has_trades"] is True

    print("\n[SUCCESS] Pre-processing correctly redacted all sensitive values.")
