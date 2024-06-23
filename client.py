from passkey import generate_passkey, get_certificate, load_private_key

import requests
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding


def authenticate(email, pin, challenge):
    private_key = load_private_key(email, pin)
    assinatura = private_key.sign(challenge, padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
        ), algorithm=hashes.SHA256())
    
    #print("assinatura: ", assinatura, "\nchallenge: ", challenge)

    return base64.b64encode(assinatura)

def registrar():
    alias = input("Digite seu nome: ")
    pin = input("Digite um pin para sua passkey: ")
    email = input("Digite seu email: ")

    generate_passkey(email, alias, pin)
    cert = get_certificate(email, pin)
    
    response = requests.post("http://localhost:5000/registrar", json={"email": email, "cert": cert.public_bytes(Encoding.PEM).decode()})

    print(response.json())
    if response.json()["success"]:
        print(f"Registro bem-sucedido ({email})")

def logar():
    email = input("Digite seu email: ")
    pin = input("Digite o pin da sua passkey: ")
    
    response = requests.post("http://localhost:5000/request-challenge", json={"email": email})


    challenge = base64.b64decode(response.json()["challenge"].encode())
    assinatura_challenge = authenticate(email, pin, challenge)

    server_response = requests.post("http://localhost:5000/authenticate", json={
        "email": email,
        "resolution": assinatura_challenge.decode()
    })

    if server_response.json()["success"]:
        print("Logado com sucesso")
    else:
        print("Erro ao logar")


if __name__ == "__main__":
    while True:
        print("Bem-vindo ao sistema:")
        print("1 - Registrar")
        print("2 - Logar")
        print("3 - Sair")
        
        opcao = int(input("Escolha uma opção: "))

        if opcao == 1:
            registrar()
        elif opcao == 2:
            logar()
        elif opcao == 3:
            exit(0)
        else:
            print("Opção inválida. Escolha novamente.")

