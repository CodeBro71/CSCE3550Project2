import pytest
from server import app, public_key
import jwt
from flask import Flask

@pytest.fixture
def client():
    with app.test_client() as test:
        yield test

# test for proper status code on auth page
def test_valid_auth_code(client):
    test = client.post("/auth")
    assert test.status_code == 200

# test to see if jwt has and exp value
def test_exp_value(client):
    test = client.post("/auth")
    data = jwt.decode(test.get_json().get("token"), public_key, "RS256")
    assert data['exp'] is not None

# checks if valid token is in the jwks
def test_valid_found(client):
    test = client.post("/auth")
    header = jwt.get_unverified_header(test.get_json().get("token"))
    assert header.get("kid") in [key["kid"] for key in client.get("/.well-known/jwks.json").get_json()["keys"]]

# checks if invalid tokens are in the jwks
def test_invalid_found(client):
    test = client.post("/auth?expired=true")
    header = jwt.get_unverified_header(test.get_json().get("token"))
    assert header.get("kid") not in [key["kid"] for key in client.get("/.well-known/jwks.json").get_json()["keys"]]