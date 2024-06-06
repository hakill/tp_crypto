from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
import flask


app = Flask(__name__)
client_shared_keys = {}

# Génération des paramètres Diffie-Helman
parametres = dh.generate_parameters(generator=2, key_size=2048)

#fonction pour calculer la cle partagee
#def calcul_shared_keys(pubK):
    #cle_partagee = pubK.exchange(pubK)
    #return cle_partagee

# Génération des clés privée et publique du serveur
privK = parametres.generate_private_key()
pubK = privK.public_key()

@app.route("/key_exchange", methods=["POST"])
def key_exchange():
    data = request.json
    client_public_key_bytes = serialization.load_pem_public_key(data["public_key"].encode())
    
    # Génération de la clé secrète partagée
    shared_key = privK.exchange(client_public_key_bytes)
    
    return jsonify({"public_key": pubK.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(), "shared_key": shared_key.hex()})

if __name__ == '__main__':
    app.run(debug=True)
