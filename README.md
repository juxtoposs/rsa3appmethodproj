# RSA Three Application Demo

A simple Python project demonstrating RSA digital signatures using three socket-based applications.

## Features
- RSA key pair generation
- Message signing and verification
- TCP socket communication
- Signature tampering simulation
- Tamper detection

## Requirements
- Python 3.10+
- cryptography library

Install dependencies:

```bash
pip install cryptography
```

## Running the Demo

### Start App 3 (Verifier)
```bash
python rsa_three_app_demo.py app3
```

### Start App 2 (Proxy / Tamper)
```bash
python rsa_three_app_demo.py app2
```

### Start App 1 (Sender)
```bash
python rsa_three_app_demo.py app1 --message "Hello RSA"
```

## How It Works
1. App 1 generates RSA keys and signs a message.
2. App 2 receives the message and can modify the signature.
3. App 3 verifies the signature and detects tampering.

## Example
Type:

```text
keep
```

in App 2 to forward the original signature unchanged.

Press Enter in App 2 to automatically tamper with the signature.

## File
- `rsa_three_app_demo.py` — main application script
