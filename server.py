import jwt
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, request, jsonify, json
import datetime
import sqlite3

# Create a database to store the keys
connection = sqlite3.connect('totally_not_my_privateKeys.db')
cursor = connection.cursor()
connection.execute('''CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)''')
connection.commit()

# generate keys
rsa_keys = rsa.generate_private_key(65537, 2048)

# serialize keys
public_key = rsa_keys.public_key().public_bytes( serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
private_key = rsa_keys.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())

# taken from provided project 1 code
def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

# insert an unexpired key into the database
exp_time = int((datetime.datetime.now() + datetime.timedelta(hours = 1)).timestamp())
cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (private_key, exp_time))
connection.commit()

# insert an expired key into the database
exp_time = int((datetime.datetime.now() - datetime.timedelta(hours = 1)).timestamp())
cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (private_key, exp_time))
connection.commit()

connection.close()

# flask for http and server handling
app = Flask(__name__)

# route and function for /auth
@app.route("/auth", methods = ["POST"])
def auth():
    payload_data = {
            "Username": "root",
            "Password": "123442069",
            "exp" : datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours = 1)
    }
    header = {}

    connection = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = connection.cursor()

    # expired case
    if request.args.get("expired") is not None:   
        header = {"kid": "expired"}

        # get the expired key from the database
        cursor.execute("SELECT key FROM keys WHERE exp < ?", (int(datetime.datetime.now().timestamp()),))
        key = cursor.fetchone()

    # unexpired case
    else:
        payload_data["exp"] += datetime.timedelta(hours = 2) 
        header = {"kid": "unexpired"}
        
        # get the unexpired key from the database
        cursor.execute("SELECT key FROM keys WHERE exp > ?", (int(datetime.datetime.now().timestamp()),))
        key = cursor.fetchone()

    connection.close()

    # return token signed with key from database
    return jsonify({"token": jwt.encode(payload_data, bytes(key[0]), "RS256", header)})

# route and function for verifying
@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    # get the unexpired key from the database
    connection = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = connection.cursor()
    cursor.execute("SELECT key FROM keys WHERE exp > ?", (int(datetime.datetime.now().timestamp()),))
    pems = cursor.fetchall()
    connection.close()

    # get the public numbers from the key
    numbers = serialization.load_pem_private_key(pems[0][0], password=None).private_numbers()

    # construct the jwks with data from the database
    jwks = {
        "keys": [
            {
                "alg": "RS256",
                "kty": "RSA",
                "use": "sig",
                "kid": "unexpired",
                "n": int_to_base64(numbers.public_numbers.n),
                "e": int_to_base64(numbers.public_numbers.e),
            }
        ]
    }

    return jsonify(jwks)

# run server on port 8080 (on localhost)
if __name__ == "__main__":
    try:
        app.run(port = 8080)
    finally:
        connection = sqlite3.connect('totally_not_my_privateKeys.db')
        cursor = connection.cursor()
        cursor.execute("DROP TABLE keys")
        connection.commit()
        connection.close()
