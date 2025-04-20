# Secure P2P Chat with Double Ratchet & SAS

![Screenshot](placeholder.png) <!-- <<< REPLACE THIS WITH YOUR SCREENSHOT -->

A secure, end-to-end encrypted peer-to-peer chat application built with Python and Tkinter, featuring the Double Ratchet algorithm (inspired by Signal) and Short Authentication String (SAS) verification for man-in-the-middle (MitM) protection.

This project aims to demonstrate the implementation of modern cryptographic protocols for secure communication in a P2P context.

## Key Features

*   **Peer-to-Peer Connection:** Direct connection between two users without a central server (after initial connection setup).
*   **End-to-End Encryption:** Messages are encrypted on the sender's device and decrypted only on the receiver's device.
*   **Double Ratchet Algorithm:** Provides advanced security properties:
    *   **Forward Secrecy:** Compromise of current keys does not compromise past messages.
    *   **Post-Compromise Security:** Compromise of current keys is mitigated for future messages once the connection heals.
*   **Short Authentication String (SAS):** Allows users to verify each other's identity out-of-band (e.g., over a phone call) to prevent MitM attacks during the initial key exchange.
*   **Cryptographic Primitives:** Uses strong, standard libraries (`cryptography`):
    *   **Identity Keys:** Ed25519 for signing.
    *   **Key Exchange:** X25519 (Curve25519 Diffie-Hellman).
    *   **Authenticated Encryption:** AES-256-GCM for message confidentiality and integrity.
    *   **Hashing:** SHA-256.
    *   **Key Derivation:** HKDF and HMAC-based KDF for ratchet steps.
*   **User Identity:** Based on cryptographic fingerprints derived from public signing keys.
*   **Simple GUI:** Built with Python's Tkinter (ttk) using a dark theme.
*   **Session Logging:** Audits key events and errors to `chat_audit.log`.

## Security Model Overview

1.  **Long-Term Identity:** Each user has a long-term Ed25519 signing key pair. The public key's fingerprint serves as the user's identifier.
2.  **Initial Connection & Key Exchange:**
    *   Users connect directly via TCP/IP.
    *   They exchange ephemeral X25519 public keys, their long-term Ed25519 public keys, an initial Double Ratchet (DHR) public key, and a nonce.
    *   This exchange is signed by their long-term Ed25519 private keys to authenticate the origin.
    *   A provisional shared secret is derived using X25519 Diffie-Hellman.
3.  **Man-in-the-Middle (MitM) Prevention:**
    *   A Short Authentication String (SAS) is derived from the hashed context of the key exchange (including both users' public keys, nonce, initial DHR keys, and the provisional shared secret).
    *   **Crucially, users MUST compare this SAS string through an independent, secure channel (e.g., phone call, in person).**
    *   If the SAS matches, they confirm, and the provisional secret becomes the initial Root Key for the Double Ratchet. If not, the connection is aborted as it indicates a potential MitM attack.
4.  **Session Encryption (Double Ratchet):**
    *   Once SAS is verified, the Double Ratchet protocol manages session keys.
    *   It uses both symmetric-key ratcheting (advancing chain keys for each message) and Diffie-Hellman ratcheting (updating keys when new DHR key pairs are exchanged) to provide Forward Secrecy and Post-Compromise Security.
    *   Each message is encrypted with a unique key derived from the current ratchet state using AES-256-GCM, which also authenticates the message content and associated data (header containing the public DHR key and message number).

## Getting Started

### Prerequisites

*   Python 3 (Tested with 3.9+, may work with older 3.x versions)
*   `pip` (Python package installer)

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/your-repo-name.git # <<< UPDATE URL
    cd your-repo-name
    ```
2.  **Install dependencies:**
    The application relies on the `cryptography` library.
    ```bash
    pip install cryptography
    ```
3.  **Run the application:**
    ```bash
    python p2p_chat_app.py
    ```

## Usage

1.  Run `p2p_chat_app.py` on two different computers (or locally using `127.0.0.1` for testing).
2.  **User A (Host):**
    *   Optionally, change the IP address if needed (defaults to `127.0.0.1`).
    *   Ensure the Port is correct (defaults to `65001`).
    *   Click the **"Host"** button. The status will change to "Listening...".
3.  **User B (Client):**
    *   Enter the **IP address** of User A in the "Peer IP" field.
    *   Ensure the **Port** matches the one User A is hosting on.
    *   Click the **"Connect"** button.
4.  **Connection & Key Exchange:** The application will automatically attempt to connect and exchange initial cryptographic keys.
5.  **!! SAS VERIFICATION !! (Critical Step):**
    *   A pop-up window will appear on **both** users' screens displaying a **Short Authentication String** (a sequence of numbers).
    *   **Users MUST communicate via a separate, trusted channel** (e.g., phone call, video chat, in person) and **verbally confirm** that the numbers they see **MATCH EXACTLY**.
    *   If the numbers match, **both** users click the **"MATCH"** button.
    *   If the numbers **DO NOT MATCH**, **at least one** user must click **"MISMATCH"** (or close the dialog). This aborts the connection, protecting against a potential Man-in-the-Middle attack. **DO NOT proceed if the SAS does not match.**
6.  **Chat:** If the SAS verification was successful, the chat interface will become active ("Secure session active"). You can now type messages and click **"Send"** (or press Enter). Messages are end-to-end encrypted using the Double Ratchet.

## Dependencies

*   [cryptography](https://cryptography.io/): The core library used for all cryptographic operations (Ed25519, X25519, AES-GCM, SHA256, HKDF, HMAC).

## License

<!-- Choose a license (e.g., MIT) and add it here -->
This project is licensed under the [MIT License](LICENSE). <!-- <<< CREATE a LICENSE file -->

## Disclaimer

**⚠️ This is a demonstration project created for educational purposes. ⚠️**

*   It has **not** undergone a formal security audit.
*   While it implements standard cryptographic primitives and the Double Ratchet concepts, there may be subtle bugs or vulnerabilities.
*   **DO NOT rely on this application for communicating highly sensitive information.**
*   Use at your own risk. The author assumes no liability for any security issues or data loss.
