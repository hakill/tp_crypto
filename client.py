import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
import flask

# Génération des paramètres DH
parametres = dh.generate_parameters(generator=2, key_size=2048, backend=None)

# Génération des clés privée et publique du client
privK = parametres.generate_private_key()
pubK = privK.public_key()

# Conversion de la clé publique en PEM
client_public_key_pem = pubK.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()

# Envoi de la clé publique au serveur
response = requests.post("http://127.0.0.1:5000/key_exchange", json={"public_key": client_public_key_pem})
server_response = response.json()

# Récupération de la clé publique du serveur
server_public_key_bytes = serialization.load_pem_public_key(server_response["public_key"].encode())

# Génération de la clé secrète partagée
shared_key = privK.exchange(server_public_key_bytes)

print("Clé secrète partagée (en hexadécimal) :", shared_key.hex())
