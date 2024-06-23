from server_side_keys import generate_server_key, get_client_certificate

import os
from flask import Flask, request, jsonify
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding
from cryptography import x509
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)
challenge = ""

@app.route("/registrar", methods=["POST"])
def registrar():
    email = request.json["email"]
    certificado = request.json["cert"].encode()

    cert = x509.load_pem_x509_certificate(certificado)

    with open(f"./server/{email}.cert", "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))
    
    print(f"Registro bem-sucedido ({email})")
    return jsonify({"success": True})

@app.route("/request-challenge", methods=["POST"])
def request_challenge():
    global challenge
    challenge = base64.b64encode(os.urandom(32)).decode()

    return jsonify({"challenge": challenge})

@app.route("/authenticate", methods=["POST"])
def authenticate():
    email = request.json["email"]
    challenge_assinatura = base64.b64decode(request.json["resolution"].encode()) #

    certificado = get_client_certificate(email)
    public_key_cliente = certificado.public_key()
    #print("assinatura: ", challenge_assinatura, "\nchallenge: ", base64.b64decode(challenge.encode()))

    try:
        public_key_cliente.verify(
                signature=challenge_assinatura, 
                data=base64.b64decode(challenge.encode()), 
                padding=padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                algorithm=hashes.SHA256())
        return jsonify({"success": True})
    except InvalidSignature as e:
       return jsonify({"success": False})


if __name__ == "__main__":
    generate_server_key()
    app.run(port=5000)
