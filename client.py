import requests
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12

def load_private_key(alias, password):
    with open(f"{alias}.p12", "rb") as f:
        p12_data = f.read()
    private_key, _, _ = pkcs12.load_key_and_certificates(p12_data, password.encode())
    return private_key

def authenticate(alias, password, challenge):
    private_key = load_private_key(alias, password)
    encrypted = private_key.decrypt(
        base64.b64decode(challenge),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def send_authentication(email):
    alias = "clientPasskey"
    password = "password"
    try:
        response = requests.post("http://localhost:5000/request-challenge", json={"email": email})
        challenge = response.json()["challenge"]
        auth_response = authenticate(alias, password, challenge)
        server_response = requests.post("http://localhost:5000/authenticate", json={
            "challenge": challenge,
            "response": auth_response
        })
        print("Resposta do servidor:", server_response.json())
    except Exception as e:
        print("Erro ao autenticar com o servidor:", e)

if __name__ == "__main__":
    email = "user@example.com"
    send_authentication(email)
