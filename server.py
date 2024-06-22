import os
from flask import Flask, request, jsonify
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12

app = Flask(__name__)

def load_private_key():
    with open("server_private_key.p12", "rb") as f:
        p12_data = f.read()
    private_key, _, _ = pkcs12.load_key_and_certificates(p12_data, b"server_password")
    return private_key

@app.route("/request-challenge", methods=["POST"])
def request_challenge():
    email = request.json["email"]
    challenge = base64.b64encode(os.urandom(32)).decode()
    print(f"Desafio gerado para o email {email}: {challenge}")
    return jsonify({"challenge": challenge})

@app.route("/authenticate", methods=["POST"])
def authenticate():
    private_key = load_private_key()
    challenge = request.json["challenge"]
    response = request.json["response"]
    try:
        decrypted = private_key.decrypt(
            base64.b64decode(response),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        is_valid = decrypted == base64.b64decode(challenge)
        print(f"Autenticação {'bem-sucedida' if is_valid else 'falhou'} para o desafio: {challenge}")
        return jsonify({"success": is_valid})
    except Exception as e:
        print("Erro ao validar a autenticação:", e)
        return jsonify({"success": False})

if __name__ == "__main__":
    app.run(port=5000)
