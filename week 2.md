Week 2 — Hybrid RSA–AES Encryption System

Secure Client–Server Communication**

📌 Overview

In this project, I implemented a hybrid cryptographic communication system that uses:

RSA (asymmetric encryption) to securely exchange a session key

AES-EAX (symmetric authenticated encryption) to protect the message

Python sockets to simulate sender/receiver communication over a network

This mirrors the design principles used in real-world secure protocols such as TLS.

🔒 Key Features

✔ RSA 2048-bit key generation

✔ AES-EAX authenticated encryption

✔ RSA-OAEP secure key encapsulation

✔ Client–server message passing over TCP

✔ Tamper detection via AES authentication tags

✔ Full hybrid encryption workflow

📂 Project Structure
/
├── generate_keys.py     # Generates private.pem & public.pem  :contentReference[oaicite:0]{index=0}
├── sender.py            # Encrypts + sends message           :contentReference[oaicite:1]{index=1}
├── receiver.py          # Receives + decrypts message        :contentReference[oaicite:2]{index=2}
├── public.pem
└── private.pem

🧠 System Architecture
            +----------------------+
            |  generate_keys.py    |
            +----------+-----------+
                       |
            public.pem | private.pem
                       |
        +--------------+--------------+
        |                             |
+-------v--------+              +------v--------+
|   sender.py    |              |  receiver.py  |
|----------------|              |---------------|
| Loads public   |              | Loads private |
| RSA key        |              | RSA key       |
| Generates AES  |              | Receives      |
| session key    |              | encrypted pkg |
| Encrypts msg   |              | Decrypts AES  |
| AES + RSA      |              | key w/ RSA    |
+--------+--------+              +-------+-------+
         |                               |
         +------------- TCP --------------+
                      Message

🚀 How to Run
1️⃣ Generate RSA Keys
python3 generate_keys.py


This produces:

private.pem (keep secret!)

public.pem (safe to share)

2️⃣ Start the Receiver
python3 receiver.py


You should see:

[Receiver] Listening on 127.0.0.1:65432 ...

3️⃣ Start the Sender
python3 sender.py


Enter any message when prompted:

Enter a message to encrypt and send: Hello world!
[Sender] Message sent!

4️⃣ Receiver Output Example
[Receiver] Connection from ('127.0.0.1', 53012)
[Receiver] Decrypted message: Hello world!

🔐 Cryptographic Workflow
1. RSA Key Generation

Using generate_keys.py (2048-bit RSA keypair).
→ Public key encrypts AES session keys
→ Private key decrypts AES session keys

2. AES Encryption in EAX Mode

AES-EAX provides:

Confidentiality

Integrity

Replay protection

3. RSA-OAEP Key Encapsulation

The AES session key is encrypted using RSA-OAEP, which:

Adds secure padding

Mitigates chosen-ciphertext attacks

Ensures safe transport over insecure channels

4. Hybrid Encryption Benefit

Hybrid systems combine the speed of AES and security of RSA—the same model used in TLS, SSH, and PGP.

🛡 Security Considerations
Security Element	Purpose
AES-EAX	Authenticated encryption, tamper detection
RSA-OAEP	Securely wraps the AES key
Random session keys	Avoid key reuse, improve secrecy
Nonces	Prevent replay attacks
Separate private key storage	Prevents decryption compromise
📘 Files Explained
🔑 generate_keys.py

Generates 2048-bit RSA keypair.


generate_keys

📨 sender.py

Encrypts message using AES-EAX and RSA-OAEP, then sends via TCP.


sender

📥 receiver.py

Decrypts AES session key with RSA and verifies message integrity.


receiver

🧩 Reflection

Through this lab, I strengthened my understanding of hybrid encryption and secure communication. 
Implementing RSA-OAEP with AES-EAX demonstrated how real-world systems balance performance, confidentiality, integrity, and key management. 
This exercise also highlighted the importance of secure key storage, nonce handling, and authenticated encryption in modern security architectures.

A longer reflection is included in my portfolio entry.
