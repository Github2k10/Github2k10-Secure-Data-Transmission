from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
import os
import base64
import time
import threading

app = Flask(__name__)

# Thread-safe key storage (consider using session or Redis in production)
key_lock = threading.Lock()

# Generate ECC key pair
def generate_ecc_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# Serialize public key for transmission
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

# Derive a symmetric key from ECC key exchange
def derive_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)
    return derived_key

# HMAC Generation and Verification
def generate_hmac(key, message):
    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(message.encode())
    return base64.b64encode(h.finalize()).decode()

def verify_hmac(key, message, hmac_to_verify):
    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(message.encode())
    try:
        h.verify(base64.b64decode(hmac_to_verify))
    except Exception:
        raise ValueError("Invalid HMAC")

# AES encryption helper
def encrypt_data(symmetric_key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

# AES decryption helper
def decrypt_data(symmetric_key, ciphertext):
    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return plaintext.decode()

# Route to provide server's public key
@app.route('/get_public_key', methods=['GET'])
def get_public_key():
    private_key, public_key = generate_ecc_key_pair()
    
    with key_lock:
        app.config['private_key'] = private_key
        app.config['key_generation_time'] = time.time()
        app.config['message_count'] = 0

    return jsonify({'public_key': serialize_public_key(public_key)})

# Replay Attack Protection
def is_message_fresh(timestamp, allowed_time_skew=300):
    current_time = time.time()
    return abs(current_time - timestamp) <= allowed_time_skew

# Route to send encrypted data
@app.route('/send_encrypted', methods=['POST'])
def send_encrypted():
    try:
        data = request.json.get('data')
        client_public_key_pem = request.json.get('client_public_key')
        timestamp = int(request.json.get('timestamp'))
        received_hmac = request.json.get('hmac')

        if not is_message_fresh(timestamp):
            return jsonify({'error': 'Replay attack detected: Message is too old'}), 400

        client_public_key = serialization.load_pem_public_key(
            client_public_key_pem.encode('utf-8'),
            backend=default_backend()
        )

        current_time = time.time()
        with key_lock:
            if current_time - app.config['key_generation_time'] > 600 or app.config['message_count'] >= 5:
                app.config['private_key'], _ = generate_ecc_key_pair()
                app.config['key_generation_time'] = current_time
                app.config['message_count'] = 0

        symmetric_key = derive_shared_key(app.config['private_key'], client_public_key)

        verify_hmac(symmetric_key, data + str(timestamp), received_hmac)

        encrypted_data = encrypt_data(symmetric_key, data)

        app.config['message_count'] += 1
        return jsonify({'encrypted_data': encrypted_data})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Route to receive and decrypt encrypted data
@app.route('/receive_encrypted', methods=['POST'])
def receive_encrypted():
    try:
        encrypted_data = request.json.get('encrypted_data')
        client_public_key_pem = request.json.get('client_public_key')
        timestamp = request.json.get('timestamp')
        received_hmac = request.json.get('hmac')

        client_public_key = serialization.load_pem_public_key(
            client_public_key_pem.encode('utf-8'),
            backend=default_backend()
        )

        symmetric_key = derive_shared_key(app.config['private_key'], client_public_key)

        verify_hmac(symmetric_key, encrypted_data + str(timestamp), received_hmac)

        decrypted_data = decrypt_data(symmetric_key, encrypted_data)

        return jsonify({'decrypted_data': decrypted_data})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Adding Secure HTTP Headers to the response
@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

if __name__ == '__main__':
    app.run(ssl_context=('cert.pem', 'key.pem'), debug=True)
