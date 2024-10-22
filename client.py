from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.backends import default_backend
import requests
import base64
import os
import time


# Generate client ECC key pair
client_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
client_public_key = client_private_key.public_key()

# Serialize the public key to send to the server
client_public_key_serialized = client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')


print("Calling get_public_key ....")
# Get the server's public key
response = requests.get('https://localhost:5000/get_public_key', verify=False)
server_public_key_pem = response.json()['public_key']
print("Public key => ", server_public_key_pem)
print("\n\r\n\r")

# Load the server's public key
server_public_key = serialization.load_pem_public_key(
    server_public_key_pem.encode('utf-8'),
    backend=default_backend()
)

# Derive a shared symmetric key using ECC
shared_key = client_private_key.exchange(ec.ECDH(), server_public_key)
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
    backend=default_backend()
).derive(shared_key)

# HMAC Generation
def generate_hmac(key, message):
    hmac = HMAC(key, hashes.SHA256(), backend=default_backend())
    hmac.update(message.encode())
    return base64.b64encode(hmac.finalize()).decode()

# Encrypt data using AES
def encrypt_data(key, plaintext):
    initialization_vector = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(initialization_vector), backend=default_backend())
    cipher_encryptor = cipher.encryptor()
    ciphertext = cipher_encryptor.update(plaintext.encode()) + cipher_encryptor.finalize()
    return base64.b64encode(initialization_vector + ciphertext).decode()

# Step 1: Prepare Data for Encryption and HMAC
data = "Temperature: 25.5, Humidity: 45.0"
timestamp = str(int(time.time()))  # Timestamp for freshness (epoch time)
data_with_timestamp = data + timestamp
encrypted_data = encrypt_data(derived_key, data)
hmac_value = generate_hmac(derived_key, data_with_timestamp)

print("Calling send_encrypted ....")
print("Payload => ", {
    'data': data,  
    'client_public_key': client_public_key_serialized,  
    'timestamp': timestamp,  
    'hmac': hmac_value 
})

# Step 2: Send the encrypted data to the server with HMAC and timestamp
response = requests.post('https://localhost:5000/send_encrypted', json={
    'data': data,  # Send raw data, server will encrypt with its own key
    'client_public_key': client_public_key_serialized,  # Send client public key
    'timestamp': timestamp,  # Add timestamp for replay protection
    'hmac': hmac_value  # Add HMAC for integrity
}, verify=False)

if response.status_code == 200:
    response_data = response.json()
    print("Server Response (Encrypted Data):", response_data)
    encrypted_data_to_send = response_data.get('encrypted_data')
else:
    print("Error response:", response.json())  # Log error response for debugging
print("\n\r\n\r")

# Step 3: Send the encrypted data back to the server for decryption
timestamp = str(int(time.time()))  # New timestamp
encrypted_data_to_send = response_data['encrypted_data']  # Access the encrypted data
hmac_value_for_encrypted = generate_hmac(derived_key, encrypted_data_to_send + timestamp)

print("Calling receive_encrypted ....")
print("Payload => ", {
    'encrypted_data': encrypted_data_to_send,  
    'client_public_key': client_public_key_serialized,  
    'timestamp': timestamp, # Add HMAC for integrity verification
})

response = requests.post('https://localhost:5000/receive_encrypted', json={
    'encrypted_data': encrypted_data_to_send,  # Send the encrypted data
    'client_public_key': client_public_key_serialized,  # Send client public key
    'timestamp': timestamp,  # Add timestamp for replay protection
    'hmac': hmac_value_for_encrypted  # Add HMAC for integrity verification
}, verify=False)

decrypted_data = response.json()
print("Server Response (Decrypted Data):", decrypted_data)
