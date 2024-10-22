from flask import request, Flask, jsonify
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import os
import time
import base64
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
    response = public_key.public_bytes(
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
        encoding=serialization.Encoding.PEM
    ).decode('utf-8')

    return response

# Derive a symmetric key from ECC key exchange
def derive_shared_key(private_key, peer_public_key):
    key_to_be_shared = private_key.exchange(ec.ECDH(), peer_public_key)

    # Derive a symmetric key from the shared key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(key_to_be_shared)

    return derived_key

def verify_HMAC(key, msg, hmac_to_verify):
    hmac = HMAC(key, hashes.SHA256(), backend=default_backend())
    hmac.update(msg.encode())

    # Verify the HMAC
    try:
        hmac.verify(base64.b64decode(hmac_to_verify))
    except Exception:
        raise ValueError("Invalid HMAC")

# AES encryption helper
def encrypt_data(symmetric_key, plaintext):
    initialization_vector = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(initialization_vector), backend=default_backend())
    
    cipher_encryptor = cipher.encryptor()
    ciphertext = cipher_encryptor.update(plaintext.encode()) + cipher_encryptor.finalize()

    return base64.b64encode(initialization_vector + ciphertext).decode()

# AES decryption helper
def decrypt_data(symmetric_key, ciphertext):
    ciphertext = base64.b64decode(ciphertext)
    initialization_vector = ciphertext[:16]

    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(initialization_vector), backend=default_backend())
    cipher_decryptor = cipher.decryptor()
    plaintext = cipher_decryptor.update(ciphertext[16:]) + cipher_decryptor.finalize()

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

        verify_HMAC(symmetric_key, data + str(timestamp), received_hmac)

        encrypted_data = encrypt_data(symmetric_key, data)

        app.config['message_count'] += 1
        return jsonify({'encrypted_data': encrypted_data})
    except Exception as e:
        return jsonify({'error => ': str(e)}), 500

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
        verify_HMAC(symmetric_key, encrypted_data + str(timestamp), received_hmac)
        decrypted_data = decrypt_data(symmetric_key, encrypted_data)

        return jsonify({'decrypted_data': decrypted_data})
    except Exception as e:
        return jsonify({'error => ': str(e)}), 500

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
