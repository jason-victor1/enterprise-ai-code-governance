import pytest
from app.tier2_data_service import UserDataService


@pytest.fixture
def data_service():
    return UserDataService()


def test_find_user_by_username_secure(data_service):
    user = data_service.find_user_by_username_secure("admin")
    assert user is not None
    assert user["username"] == "admin"
    assert user["role"] == "SuperAdmin"


def test_find_user_not_found(data_service):
    user = data_service.find_user_by_username_secure("nonexistent")
    assert user is None
