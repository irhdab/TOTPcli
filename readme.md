
# TOTPcli - TOTP Command Line Interface

A lightweight Python CLI tool for generating TOTP codes from your 2FA secrets. Compatible with services like Google Authenticator, GitHub, AWS, and other RFC 6238-compliant implementations.

## Features
- Generate TOTP codes from terminal
- Store secrets securely in local configuration
- Simple CLI interface
- Cross-platform compatibility

## Installation
1. Clone repository:
```
git clone https://github.com/irhdab/TOTPcli.git](https://github.com/irhdab/TOTPcli.git
 cd TOTPcli
```
2. Install requirements:
```
pip install -r requirements.txt
```


## Usage
### Basic Authentication Code Generation
python 2fa.py [service-name]

### Add New TOTP Secret
python 2fa.py add [service-name]

### List Configured Services
python 2fa.py list

## Configuration
### Secrets are stored in `~/.2fa_config.json` by default. The file format uses:
[service-name] secret = YOUR_BASE32_SECRET

## Requirements(Pyhton3&requirements.txt
- Python 3.7+
- `pyotp` library
- `cryptography` for optional encryption
