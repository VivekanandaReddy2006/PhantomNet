import requests
import pytest

import os
import socket

BASE_URL = os.environ.get("HTTP_URL", "http://localhost:8080")

def check_url_reachable(url):
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname or "localhost"
        port = parsed.port or (80 if parsed.scheme == "http" else 443)
        with socket.create_connection((host, port), timeout=1.0):
            return True
    except OSError:
        return False

if not check_url_reachable(BASE_URL):
    pytestmark = pytest.mark.skip(reason=f"HTTP honeypot not running on {BASE_URL}")


def test_get_admin():
    """Admin page should load"""
    r = requests.get(f"{BASE_URL}/admin")
    assert r.status_code == 200
    assert "Admin Dashboard" in r.text


def test_post_admin():
    """Login attempt should fail but be accepted"""
    r = requests.post(
        f"{BASE_URL}/admin", data={"username": "admin", "password": "1234"}
    )
    assert r.status_code == 403
    assert "Invalid credentials" in r.text


def test_put_admin():
    """PUT should be forbidden"""
    r = requests.put(f"{BASE_URL}/admin")
    assert r.status_code == 403


def test_delete_admin():
    """DELETE should return not found"""
    r = requests.delete(f"{BASE_URL}/admin")
    assert r.status_code == 404
