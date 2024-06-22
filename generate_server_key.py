from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

def generate_server_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    p12_data = pkcs12.serialize_key_and_certificates(
        name=b"server",
        key=key,
        cert=None,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(b"server_password")
    )
    with open("server_private_key.p12", "wb") as f:
        f.write(p12_data)

if __name__ == "__main__":
    generate_server_key()
