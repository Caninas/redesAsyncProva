import base64
import requests
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class Client:
    def __init__(self):
        self.key_store = {}

    def authenticate(self, alias, password, challenge):
        # Lê o arquivo .p12 do disco
        with open(f"{alias}.p12", 'rb') as p12_file:
            p12_data = p12_file.read()

        private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
            p12_data,
            password.encode(),
            default_backend()
        )

        # Criptografa o desafio usando a chave pública
        public_key = certificate.public_key()
        encrypted = public_key.encrypt(
            challenge.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Retorna a resposta criptografada em base64
        return base64.b64encode(encrypted).decode()

    def send_authentication(self, email):
        alias = 'clientPasskey'
        password = 'password'

        try:
            # Solicita um desafio do servidor
            challenge_response = requests.post('http://localhost:5000/request-challenge', json={'email': email})
            challenge = challenge_response.json()['challenge']

            # Autentica usando o desafio recebido
            response = self.authenticate(alias, password, challenge)

            # Envia a resposta de autenticação para o servidor
            server_response = requests.post('http://localhost:5000/authenticate', json={
                'challenge': challenge,
                'response': response
            })

            print('Resposta do servidor:', server_response.json())
        except Exception as e:
            print('Erro ao autenticar com o servidor:', e)

# Envia a autenticação para o servidor
client = Client()
email = 'user@example.com'
client.send_authentication(email)
