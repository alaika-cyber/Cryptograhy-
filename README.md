# CipherCanvas - Advanced Cryptography and Steganography Tool

CipherCanvas is a browser-based crypto + stego lab that can encrypt, decrypt, hide text in images, and hide full image files in other images.

## Core Features

- AES-GCM with PBKDF2-SHA256 for passphrase encryption.
- RSA-OAEP + AES hybrid encryption.
- ECDH-P256 + AES hybrid encryption.
- Caesar and Vigenere (educational ciphers).
- Text-in-image steganography and extraction.
- Image-in-image steganography and extraction.
- Optional AES protection for hidden payloads.

## Power Features Added

- Versioned stego container format (`STG2`) with payload checksum (CRC32).
- Stricter payload validation for malformed ciphertext and metadata.
- Capacity meter for carrier images.
- Copy and download actions for crypto output.
- Guided workflow buttons:
	- Encrypt -> Fill Secret Text
	- Extract -> Load Crypto Input
- RSA key helpers:
	- Generate, save, load
	- Public key fingerprint display
- ECDH key helpers:
	- Generate, save, load
- Drag-and-drop support for image inputs.
- Preview cards for selected files.
- Operation progress bars for hide/extract tasks.

## Run

Option 1 (direct):

1. Open [index.html](index.html) in a modern browser.

Option 2 (local server):

1. Run `python3 run.py`
2. Open `http://127.0.0.1:8000`

## Usage Notes

- Use PNG carriers for best reliability.
- JPEG can corrupt hidden bits due to lossy compression.
- Encoded output is always generated as PNG.
- Capacity depends on carrier resolution.
- RSA and ECDH keys are stored in browser local storage only when you press Save.

## Security Notes

- Classical ciphers (Caesar, Vigenere) are for learning only.
- Local storage key saving is convenient but less secure than dedicated key vaults.
- For high-assurance production systems, use audited cryptographic tooling, secure key management, and independent security review.