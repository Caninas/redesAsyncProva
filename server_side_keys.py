import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509

def generate_server_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    p12_data = pkcs12.serialize_key_and_certificates(
        name=b"server",
        key=key,
        cert=None,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(b"server_password")
    )
    
    try:
        os.mkdir("./server")
    except Exception as e:
        if e.__class__.__name__ != "FileExistsError":
            print("Erro ao criar pasta:", e)
         
    with open("./server/server_private_key.p12", "wb") as f:
        f.write(p12_data)

def get_client_certificate(email):
    with open(f"./server/{email}.cert", "rb") as f:
        cert_data = f.read()
    cert = x509.load_pem_x509_certificate(cert_data)
    return cert

if __name__ == "__main__":
    generate_server_key()
