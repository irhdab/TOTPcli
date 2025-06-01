import argparse
import base64
import hashlib
import hmac
import json
import os
import struct
import time
import urllib.parse
import threading
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass
import qrcode

class TOTPManager:
    def __init__(self, config_file="~/.2fa_config.json"):
        self.config_file = os.path.expanduser(config_file)
        self.accounts = {}
        self.cipher = None
        self._stop_auto_renewal = False
        
    def derive_key(self, password, salt):
        """Derive encryption key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def encrypt_data(self, data, password):
        """Encrypt account data"""
        salt = os.urandom(16)
        key = self.derive_key(password, salt)
        f = Fernet(key)
        encrypted_data = f.encrypt(json.dumps(data).encode())
        return {
            'salt': base64.b64encode(salt).decode(),
            'data': base64.b64encode(encrypted_data).decode()
        }
    
    def decrypt_data(self, encrypted_info, password):
        """Decrypt account data"""
        salt = base64.b64decode(encrypted_info['salt'])
        encrypted_data = base64.b64decode(encrypted_info['data'])
        key = self.derive_key(password, salt)
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())
    
    def load_accounts(self, password):
        """Load accounts from encrypted config file"""
        if not os.path.exists(self.config_file):
            self.accounts = {}
            return
        
        try:
            with open(self.config_file, 'r') as f:
                encrypted_info = json.load(f)
            self.accounts = self.decrypt_data(encrypted_info, password)
        except Exception as e:
            raise Exception(f"Failed to decrypt config file. Wrong password? Error: {e}")
    
    def save_accounts(self, password):
        """Save accounts to encrypted config file"""
        encrypted_info = self.encrypt_data(self.accounts, password)
        with open(self.config_file, 'w') as f:
            json.dump(encrypted_info, f)
        # Set restrictive permissions
        os.chmod(self.config_file, 0o600)
    
    def normalize_secret(self, secret):
        """Normalize and validate secret key"""
        # Remove spaces and convert to uppercase
        secret = secret.replace(' ', '').replace('-', '').upper()
        
        # Add padding if needed
        missing_padding = len(secret) % 8
        if missing_padding:
            secret += '=' * (8 - missing_padding)
        
        return secret
    
    def generate_totp(self, secret, timestamp=None):
        """Generate TOTP code from secret"""
        if timestamp is None:
            timestamp = int(time.time())
        
        # Normalize the secret
        try:
            normalized_secret = self.normalize_secret(secret)
            secret_bytes = base64.b32decode(normalized_secret)
        except Exception as e:
            raise ValueError(f"Invalid secret key format: {str(e)}")
        
        # Calculate time counter (30-second intervals)
        counter = timestamp // 30
        
        # Convert counter to bytes
        counter_bytes = struct.pack('>Q', counter)
        
        # Generate HMAC-SHA1 hash
        hmac_hash = hmac.new(secret_bytes, counter_bytes, hashlib.sha1).digest()
        
        # Dynamic truncation
        offset = hmac_hash[-1] & 0xF
        truncated = struct.unpack('>I', hmac_hash[offset:offset + 4])[0]
        truncated &= 0x7FFFFFFF
        
        # Generate 6-digit code
        code = truncated % 1000000
        return f"{code:06d}"
    
    def add_account(self, name, secret, issuer=None):
        """Add a new account"""
        # Clean and validate secret
        try:
            # Test if secret works by generating a code
            self.generate_totp(secret)
        except ValueError as e:
            raise ValueError(f"Invalid secret: {e}")
        
        # Store the normalized secret
        normalized_secret = self.normalize_secret(secret)
        self.accounts[name] = {
            'secret': normalized_secret,
            'issuer': issuer or name,
            'added': int(time.time())
        }
    
    def update_account(self, name, secret=None, issuer=None, new_name=None):
        """Update an existing account"""
        if name not in self.accounts:
            raise KeyError(f"Account '{name}' not found")
        
        # Validate new secret if provided
        if secret:
            try:
                self.generate_totp(secret)
                normalized_secret = self.normalize_secret(secret)
            except ValueError as e:
                raise ValueError(f"Invalid secret: {e}")
        
        # Store current account data
        account_data = self.accounts[name].copy()
        
        # Update fields
        if secret:
            account_data['secret'] = normalized_secret
        if issuer:
            account_data['issuer'] = issuer
        
        # Update last modified timestamp
        account_data['modified'] = int(time.time())
        
        # Handle name change
        if new_name and new_name != name:
            if new_name in self.accounts:
                raise ValueError(f"Account '{new_name}' already exists")
            # Remove old entry and add with new name
            del self.accounts[name]
            self.accounts[new_name] = account_data
            return new_name
        else:
            # Update existing entry
            self.accounts[name] = account_data
            return name
    
    def remove_account(self, name):
        """Remove an account"""
        if name not in self.accounts:
            raise KeyError(f"Account '{name}' not found")
        del self.accounts[name]
    
    def list_accounts(self):
        """List all accounts"""
        return list(self.accounts.keys())
    
    def get_account_info(self, name):
        """Get detailed information about an account"""
        if name not in self.accounts:
            raise KeyError(f"Account '{name}' not found")
        
        account = self.accounts[name]
        info = {
            'name': name,
            'issuer': account['issuer'],
            'added': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(account['added']))
        }
        
        if 'modified' in account:
            info['modified'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(account['modified']))
        
        return info
    
    def get_code(self, name):
        """Get current TOTP code for account"""
        if name not in self.accounts:
            raise KeyError(f"Account '{name}' not found")
        
        secret = self.accounts[name]['secret']
        code = self.generate_totp(secret)
        
        # Calculate time remaining
        current_time = int(time.time())
        time_remaining = 30 - (current_time % 30)
        
        return code, time_remaining
    
    def get_all_codes(self):
        """Get current codes for all accounts"""
        codes = {}
        for name in self.accounts:
            code, time_remaining = self.get_code(name)
            codes[name] = {
                'code': code,
                'time_remaining': time_remaining,
                'issuer': self.accounts[name]['issuer']
            }
        return codes
    
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def display_codes_live(self, account_name=None, refresh_interval=1):
        """Display TOTP codes with live updates"""
        self._stop_auto_renewal = False
        
        def signal_handler(signum, frame):
            self._stop_auto_renewal = True
            print("\nStopping auto-renewal...")
            sys.exit(0)
        
        # Handle Ctrl+C gracefully
        import signal
        signal.signal(signal.SIGINT, signal_handler)
        
        print("Live TOTP Codes (Press Ctrl+C to stop)")
        print("=" * 50)
        
        last_codes = {}
        
        try:
            while not self._stop_auto_renewal:
                current_time = int(time.time())
                time_in_cycle = current_time % 30
                time_remaining = 30 - time_in_cycle
                
                # Clear screen for clean display
                if os.name == 'nt':  # Windows
                    os.system('cls')
                else:  # Unix/Linux/Mac
                    os.system('clear')
                
                print(f"Live TOTP Codes - {time.strftime('%H:%M:%S')}")
                print("=" * 50)
                
                if account_name:
                    # Show single account
                    if account_name in self.accounts:
                        code, remaining = self.get_code(account_name)
                        issuer = self.accounts[account_name]['issuer']
                        
                        # Highlight if code changed
                        indicator = "🔄" if last_codes.get(account_name) != code else "  "
                        
                        print(f"{indicator} {account_name} ({issuer})")
                        print(f"    Code: {code}")
                        print(f"    Expires in: {remaining}s")
                        
                        # Progress bar
                        progress = int((remaining / 30) * 20)
                        bar = "█" * progress + "░" * (20 - progress)
                        print(f"    [{bar}] {remaining:2d}s")
                        
                        last_codes[account_name] = code
                    else:
                        print(f"Account '{account_name}' not found")
                        break
                else:
                    # Show all accounts
                    codes = self.get_all_codes()
                    if codes:
                        for name, info in sorted(codes.items()):
                            # Highlight if code changed
                            indicator = "🔄" if last_codes.get(name) != info['code'] else "  "
                            
                            print(f"{indicator} {name} ({info['issuer']})")
                            print(f"    Code: {info['code']}")
                            
                            last_codes[name] = info['code']
                        
                        print(f"\nAll codes expire in: {time_remaining}s")
                        # Global progress bar
                        progress = int((time_remaining / 30) * 30)
                        bar = "█" * progress + "░" * (30 - progress)
                        print(f"[{bar}] {time_remaining:2d}s")
                    else:
                        print("No accounts configured")
                        break
                
                # Update every second, but force refresh when codes change
                if time_remaining <= 1:
                    time.sleep(time_remaining + 0.1)  # Wait for new cycle
                else:
                    time.sleep(refresh_interval)
                    
        except KeyboardInterrupt:
            print("\nStopped by user")
        except Exception as e:
            print(f"\nError during live display: {e}")
    
    def watch_codes(self, account_name=None):
        """Watch codes with auto-renewal (alias for display_codes_live)"""
        self.display_codes_live(account_name)
    
    def parse_otpauth_url(self, url):
        """Parse otpauth:// URL"""
        if not url.startswith('otpauth://totp/'):
            raise ValueError("Invalid otpauth URL format")
        
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        # Extract account name
        account_name = urllib.parse.unquote(parsed.path[1:])  # Remove leading /
        if ':' in account_name:
            issuer, account = account_name.split(':', 1)
        else:
            issuer = params.get('issuer', [account_name])[0]
            account = account_name
        
        secret = params.get('secret', [None])[0]
        if not secret:
            raise ValueError("No secret found in URL")
        
        return account, secret, issuer

def main():
    parser = argparse.ArgumentParser(description='TOTP 2FA CLI Manager with Auto-Renewal')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Add account
    add_parser = subparsers.add_parser('add', help='Add a new account')
    add_parser.add_argument('name', help='Account name')
    add_parser.add_argument('--secret', help='Base32 secret key')
    add_parser.add_argument('--url', help='otpauth:// URL')
    add_parser.add_argument('--issuer', help='Issuer name')
    
    # Update account
    update_parser = subparsers.add_parser('update', help='Update an existing account')
    update_parser.add_argument('name', help='Current account name')
    update_parser.add_argument('--secret', help='New Base32 secret key')
    update_parser.add_argument('--issuer', help='New issuer name')
    update_parser.add_argument('--new-name', help='New account name')
    update_parser.add_argument('--url', help='New otpauth:// URL')
    
    # Remove account
    remove_parser = subparsers.add_parser('remove', help='Remove an account')
    remove_parser.add_argument('name', help='Account name')
    
    # List accounts
    list_parser = subparsers.add_parser('list', help='List all accounts')
    list_parser.add_argument('--detailed', '-d', action='store_true', help='Show detailed information')
    
    # Get code (one-time)
    code_parser = subparsers.add_parser('code', help='Get TOTP code for account (one-time)')
    code_parser.add_argument('name', nargs='?', help='Account name (optional - shows all if omitted)')
    
    # Watch codes (live auto-renewal)
    watch_parser = subparsers.add_parser('watch', help='Watch TOTP codes with auto-renewal')
    watch_parser.add_argument('name', nargs='?', help='Account name (optional - shows all if omitted)')
    watch_parser.add_argument('--interval', '-i', type=int, default=1, help='Refresh interval in seconds (default: 1)')
    
    # Live codes (alias for watch)
    live_parser = subparsers.add_parser('live', help='Live TOTP codes with auto-renewal (alias for watch)')
    live_parser.add_argument('name', nargs='?', help='Account name (optional - shows all if omitted)')
    live_parser.add_argument('--interval', '-i', type=int, default=1, help='Refresh interval in seconds (default: 1)')
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Test a secret key without saving')
    test_parser.add_argument('secret', help='Secret key to test')
    
    # Generate QR code
    qr_parser = subparsers.add_parser('qr', help='Generate QR code for manual entry')
    qr_parser.add_argument('name', help='Account name')
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Show detailed information about an account')
    info_parser.add_argument('name', help='Account name')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    totp = TOTPManager()
    
    # Get password
    password = getpass.getpass("Enter master password: ")
    
    try:
        totp.load_accounts(password)
    except Exception as e:
        if "Failed to decrypt" in str(e):
            print(f"Error: {e}")
            return
        # File doesn't exist or other error, continue with empty accounts
        pass
    
    try:
        if args.command == 'add':
            if args.url:
                name, secret, issuer = totp.parse_otpauth_url(args.url)
                totp.add_account(name, secret, issuer)
                print(f"Added account: {name}")
            elif args.secret:
                totp.add_account(args.name, args.secret, args.issuer)
                print(f"Added account: {args.name}")
            else:
                secret = getpass.getpass("Enter secret key: ")
                totp.add_account(args.name, secret, args.issuer)
                print(f"Added account: {args.name}")
            
            totp.save_accounts(password)
        
        elif args.command == 'update':
            if args.url:
                _, secret, issuer = totp.parse_otpauth_url(args.url)
                updated_name = totp.update_account(args.name, secret=secret, issuer=issuer, new_name=args.new_name)
            else:
                updated_name = totp.update_account(args.name, secret=args.secret, issuer=args.issuer, new_name=args.new_name)
            
            print(f"Updated account: {updated_name}")
            totp.save_accounts(password)
        
        elif args.command == 'remove':
            totp.remove_account(args.name)
            print(f"Removed account: {args.name}")
            totp.save_accounts(password)
        
        elif args.command == 'list':
            accounts = totp.list_accounts()
            if accounts:
                if args.detailed:
                    print("Accounts (detailed):")
                    for name in accounts:
                        info = totp.get_account_info(name)
                        print(f"  Name: {info['name']}")
                        print(f"  Issuer: {info['issuer']}")
                        print(f"  Added: {info['added']}")
                        if 'modified' in info:
                            print(f"  Modified: {info['modified']}")
                        print()
                else:
                    print("Accounts:")
                    for name in accounts:
                        issuer = totp.accounts[name]['issuer']
                        print(f"  {name} ({issuer})")
            else:
                print("No accounts configured")
        
        elif args.command == 'info':
            info = totp.get_account_info(args.name)
            print(f"Account Information:")
            print(f"  Name: {info['name']}")
            print(f"  Issuer: {info['issuer']}")
            print(f"  Added: {info['added']}")
            if 'modified' in info:
                print(f"  Modified: {info['modified']}")
        
        elif args.command == 'code':
            if args.name:
                code, time_remaining = totp.get_code(args.name)
                print(f"{args.name}: {code} (expires in {time_remaining}s)")
            else:
                codes = totp.get_all_codes()
                if codes:
                    print("Current codes:")
                    for name, info in codes.items():
                        print(f"  {name}: {info['code']} (expires in {info['time_remaining']}s)")
                else:
                    print("No accounts configured")
        
        elif args.command in ['watch', 'live']:
            if not totp.accounts:
                print("No accounts configured")
                return
            
            totp.display_codes_live(args.name, args.interval)
        
        elif args.command == 'test':
            try:
                code = totp.generate_totp(args.secret)
                print(f"Secret key is valid!")
                print(f"Current TOTP code: {code}")
                normalized = totp.normalize_secret(args.secret)
                print(f"Normalized secret: {normalized}")
            except Exception as e:
                print(f"Error testing secret: {e}")
                return
        
        elif args.command == 'qr':
            if args.name not in totp.accounts:
                print(f"Account '{args.name}' not found")
                return
            
            account = totp.accounts[args.name]
            url = f"otpauth://totp/{account['issuer']}:{args.name}?secret={account['secret']}&issuer={account['issuer']}"
            
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(url)
            qr.make(fit=True)
            qr.print_ascii()
    
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    main()