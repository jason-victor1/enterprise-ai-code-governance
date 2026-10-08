"""
DEMONSTRATION OF THE TAUTOLOGICAL TESTING TRAP:
An AI agent generated both the vulnerable method and this test.
Notice that this test passes 100% green despite executing the vulnerable string-formatting query,
proving that high code coverage without mutation testing provides false confidence.
"""
from app.tier2_data_service import UserDataService


def test_tautological_user_retrieval():
    service = UserDataService()
    # The agent asserts its own fragile query behavior:
    result = service.find_user_by_username_insecure("developer")
    assert result is not None
    assert result["email"] == "dev@corp.internal"
    # This assertion passes green, concealing the underlying injection vulnerability
    # and lack of boundary parameterization!
