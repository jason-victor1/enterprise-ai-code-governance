"""
test_properties.py
------------------
Hypothesis property-based fuzz tests to mathematically verify that
database query lookups maintain invariants under arbitrary input permutations
(special characters, quotes, null bytes, long strings).
"""
import pytest
from hypothesis import given, strategies as st
from app.tier2_data_service import UserDataService


@pytest.fixture(scope="module")
def persistent_service():
    return UserDataService()


@given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=100))
def test_property_parameterized_query_invariance(persistent_service, input_username):
    """
    Property:
    The secure parameterized query must NEVER raise a sqlite3 syntax or injection exception,
    regardless of input content (e.g., `' OR '1'='1`, quotes, newlines, special characters).
    It must safely return either a valid dict or None.
    """
    result = persistent_service.find_user_by_username_secure(input_username)
    assert result is None or isinstance(result, dict)


def test_adversarial_sqli_payload_resilience(persistent_service):
    """Verifies that classic SQL injection payloads are safely neutralized."""
    sqli_payloads = [
        "' OR '1'='1",
        "admin' --",
        "'; DROP TABLE users; --",
        "' UNION SELECT 1, 'hacked', 'hack@corp.internal', 'SuperAdmin' --"
    ]
    for payload in sqli_payloads:
        result = persistent_service.find_user_by_username_secure(payload)
        # Injection payload should not match legitimate admin user
        assert result is None or result["username"] != "admin"
