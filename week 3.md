Week 3 — Authentication and Access Control
1. Overview

In Week 3, I implemented a complete authentication system incorporating modern security controls such as password-strength evaluation, secure hashing with salt and pepper, bcrypt storage, brute-force attack simulation, and Time-based One-Time Passwords (TOTP) for two-factor authentication (2FA).

This lab demonstrates how authentication must combine policy, cryptography, and verification mechanisms to resist real threats such as credential stuffing, brute force attacks, rainbow tables, and password database leaks.

The practical work builds a Python-based authentication module that mimics real-world login workflows used by platforms like Google, GitHub, and Microsoft 365.

2. Objectives

By completing this lab, I aimed to:

Implement password-strength evaluation using entropy and character-set analysis

Understand weaknesses of unsalted hashing and rainbow-table attacks

Apply salts and peppers to strengthen SHA-256 password hashing

Demonstrate bcrypt as an adaptive, slow hashing function designed for password storage

Implement TOTP-based 2FA using RFC 6238

Generate QR codes for provisioning into authenticator apps

Build an authentication class enforcing strong passwords + 2FA

Simulate dictionary attacks to demonstrate why secure hashing matters

3. System Architecture

Below is an ASCII diagram illustrating the components of the authentication system:

                     +-----------------------+
                     |  Password Strength    |
                     |  Evaluation Module    |
                     +----------+------------+
                                |
                                v
        +--------------- User Registration ----------------+
        |                                                  |
        |   +---------------+       +-------------------+  |
        |   |  bcrypt Hash  | <---- |  Salt + Pepper    |  |
        |   +---------------+       +-------------------+  |
        |                                                  |
        +-----------------------+--------------------------+
                                |
                                v
                  +-----------------------------+
                  |     TOTP 2FA Generator      |
                  |  - Base32 secret            |
                  |  - QR provisioning          |
                  |  - 30-second rotating code  |
                  +-------------+---------------+
                                |
                                v
                +-------------------------------+
                |        Authentication         |
                | - bcrypt password check       |
                | - TOTP verification (2FA)     |
                +-------------------------------+



This system implements layered authentication security identical to how modern identity systems operate.

4. Implementation

The following section explains each major component of the Week 3 code.

4.1 Password Strength Evaluation

The password-strength function examines:

Length

Presence of lowercase, uppercase, digits, symbols

Character pool size

Approximate Shannon entropy

Checks against a dictionary of common bad passwords

def password_strength(password: str) -> dict:
    ...


This prevents weak credentials at registration time.
The system rejects weak or common passwords, improving resistance to credential stuffing and brute-force attacks.

4.2 Hashing: Salt, Pepper, and SHA-256 Demonstration

To illustrate the dangers of simple hashing, I implemented:

No salt
sha256(password)


→ Produces identical hashes for identical passwords
→ Vulnerable to rainbow tables

With salt
sha256(salt + password)


→ Unique output even if two users choose the same password

With salt + pepper
sha256(pepper + salt + password)


→ Pepper stored separately (environment variable)
→ Protects even if database leaks

These demonstrations clearly show how incremental improvements in hashing strengthen password storage.

4.3 bcrypt — The Industry Standard for Password Storage

bcrypt is intentionally slow and uses a work factor.
This means attackers cannot brute-force 10 billion hashes per second like they could with SHA-256.

def hash_bcrypt(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


bcrypt adds:

Built-in salt

Adaptive cost factor

Resistance to GPU cracking

This is the correct method to store real passwords.

4.4 Dictionary Attack Simulation

A small brute-force demonstration shows how MD5 and SHA-256 hash functions are vulnerable to fast cracking:

simulate_bruteforce_sha("password", "md5")
simulate_bruteforce_sha("password", "sha256")


The system attempts common passwords to highlight:

How fast attackers can brute force unsalted hashes

Why slow hashing functions like bcrypt are required

4.5 TOTP (Two-Factor Authentication)

Using the pyotp library, I created a full TOTP workflow:

Secret generation
secret = pyotp.random_base32()

TOTP provisioning URI
uri = totp.provisioning_uri(name=username, issuer_name="MySecureApp")

QR code generation
qrcode.make(uri).save("totp_qr.png")


This can be scanned by:

Google Authenticator

Microsoft Authenticator

Authy

TOTP code verification
totp.verify(code)


This adds a second factor, preventing account takeover even if a password leaks.

4.6 Full Authentication System

The AuthSystem class handles the complete lifecycle:

Registration

Checks password strength

Hashes password with bcrypt

Generates a TOTP secret

Stores credentials securely

Authentication

bcrypt password verification

Optional or required TOTP verification

if not verify_bcrypt(password, user.password_hash):
    return False
if not verify_totp_code(user.totp_secret, totp_code):
    return False


The result is a modern, layered authentication model.

5. Testing the System
User Registration

Example:

User 'alice' registered successfully.
TOTP secret: JBSWY3DPEHPK3PXP

Authentication with correct password + TOTP
Authentication successful!

Wrong password
Invalid password.

Wrong TOTP
Invalid TOTP code.


Successful testing confirms the system enforces:

Strong passwords

Secure password storage

Multi-factor authentication

6. Security Analysis (Expert Level)
✔ Password Strength & Entropy

Weak passwords exponentially reduce security.
This system enforces complexity & entropy to mitigate guessing attacks.

✔ Hashing, Salt, Pepper

Salt: Stops rainbow-table attacks

Pepper: Adds server-side secret for an additional layer

bcrypt: Makes brute-force attacks computationally expensive

✔ TOTP (2FA)

Prevents account compromise when a password is leaked.
Uses time-shifting window safety to compensate for clock drift.

✔ Attack Surface Considerations
Threat	Mitigation
Credential stuffing	Strong password policy + 2FA
Brute force	bcrypt’s slow hashing
Database breach	Salt + pepper + bcrypt
MitM attacks	TOTP codes cannot be reused
Replay attacks	TOTP uses time-based rotation
✔ Limitations

No rate-limiting implemented

No account blocking after repeated failures

No secure storage mechanism for peppers demonstrated

These are expected additions in production environments.

7. Reflection

This week’s lab deepened my understanding of how authentication systems must be designed to resist practical attacks. 
Implementing entropy-based password validation, hashing layers, and 2FA clarified how interconnected each security mechanism is.

By building the system myself, I gained practical insight into:

Why SHA-256 is unsuitable for password storage

How salts, peppers, and bcrypt mitigate attack vectors

How TOTP implements something you have, complementing passwords (something you know)

Why multi-factor authentication dramatically reduces account takeover risk

If I were to expand the system further, I would add:

Account lockout and rate-limiting

Secure session tokens

Recovery codes

Web-based front-end authentication flow

Integration with OAuth or SSO models

This lab gave me a strong understanding of modern authentication practices used across industry-level systems.
