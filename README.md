# Secure Data Transmission Using Advanced Encryption Techniques

This project presents a secure end-to-end encryption solution for IoT data transmission, leveraging advanced encryption techniques such as Elliptic Curve Cryptography (ECC) and Post-Quantum Cryptography (PQC). The project implements secure communication protocols ( TLS/SSL, HTTP/1.1,), focuses on mitigating potential threats (e.g., Man-in-the-Middle attacks), and optimizes encryption performance.

The solution ensures IoT sensor data is securely transmitted and protected from real-world threats, with dynamic key management and cutting-edge encryption algorithms. The project also incorporates metrics to assess the performance impact of the implemented cryptographic techniques, providing both security and efficiency.

## **Project Scope**

The key objectives of this project include:

1. **Advanced Encryption Techniques**:
    - Elliptic Curve Cryptography (ECC) for key exchange.
    - AES for data encryption.
    - HMAC for data integrity.
    - Exploration of Post-Quantum Cryptography (PQC) for future-proofing.
2. **Enhanced Protocols**:
    - Secure communication using  TLS/SSL.
    - HTTP/1.1  for improved data transfer security and performance.
3. **Threat Mitigation**:
    - Protection against Man-in-the-Middle (MitM) attacks.
    - Replay attack prevention using timestamps and HMAC validation.
4. **Performance Optimization**:
    - Evaluation of encryption algorithms’ impact on data transmission speed and system performance.
5. **Customizable Data Simulation**:
    - Advanced data simulation with encryption analysis and visualization tools for assessing encryption methods' performance and impact.

<br> <br>

# **Implementation Details**

### **Server-Side (Flask Application)**

The **server** was developed using **Flask** and is responsible for managing key exchanges, encrypting and decrypting data, and ensuring the integrity of the communication:

- **ECC Key Pair Generation**: The server generates an ECC key pair to initiate secure communication.
- **AES Encryption**: Data received from the client is encrypted using AES with a shared symmetric key derived from the ECC key exchange.
- **HMAC Verification**: The server verifies the HMAC to ensure message integrity.
- **Replay Attack Protection**: Timestamp validation ensures that messages are fresh and replay attacks are prevented.

### **Client-Side (IoT Simulation)**

The **client** simulates an IoT device and performs the following tasks:

- **ECC Key Pair Generation**: The client generates an ECC key pair and shares its public key with the server.
- **Data Encryption**: The client encrypts the data before sending it to the server.
- **HMAC Generation**: The client generates an HMAC to protect the integrity of the data.
- **Replay Protection**: The client includes a timestamp in each message to avoid replay attacks.

### **Code Overview**

- **app.py (Server-Side)**: Manages ECC key exchange, AES encryption/decryption, HMAC verification, and communication with the client.
- **client.py (Client-Side)**: Simulates an IoT device that encrypts and transmits sensor data to the server, while validating security features such as HMAC and replay attack protection.

# **Usage**

To download and unzip the file attached bottom of this file, and follow the steps to run the application.

create a `virtual-environment` where we can start the application by following command:

```python
python -m venv venv
```

next activate the `virtual-environment` , by following the command:

```python
source env/bin/activate
```

now, install the required libraries to run the application:

```python
pip install -r requirements.txt
```

Here everything is ready to start the application. So, open two tabs in the terminal. In one tab we will start the server, and in second tab we will call the API’s.

```
# Run this command in one tab to start the flask server:
		python app.py
		
# Run this command in second tab to call and check the execution of the API's
		python client.py
```

<br>

# **Conclusion**

This project successfully implemented a secure and efficient system for IoT data transmission using advanced encryption techniques. By integrating **ECC** for key exchange, **AES** for data encryption, and **HMAC** for message integrity, the system provides robust protection against real-world security threats such as MitM and replay attacks.