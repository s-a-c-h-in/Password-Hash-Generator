import hashlib
import bcrypt
import getpass
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

def md5_hash(password):
    """Generate MD5 hash"""
    return hashlib.md5(password.encode()).hexdigest()

def sha1_hash(password):
    """Generate SHA1 hash"""
    return hashlib.sha1(password.encode()).hexdigest()

def sha256_hash(password):
    """Generate SHA256 hash"""
    return hashlib.sha256(password.encode()).hexdigest()

def sha512_hash(password):
    """Generate SHA512 hash"""
    return hashlib.sha512(password.encode()).hexdigest()

def blake2b_hash(password):
    """Generate BLAKE2b hash"""
    return hashlib.blake2b(password.encode()).hexdigest()

def blake2s_hash(password):
    """Generate BLAKE2s hash"""
    return hashlib.blake2s(password.encode()).hexdigest()

def bcrypt_hash(password):
    """Generate bcrypt hash (with salt)"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def pbkdf2_hash(password):
    """Generate PBKDF2 hash"""
    salt = os.urandom(32)  # 32 bytes salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    # Return salt + hash encoded in base64
    return base64.b64encode(salt + key).decode('utf-8')

def sha3_256_hash(password):
    """Generate SHA3-256 hash"""
    return hashlib.sha3_256(password.encode()).hexdigest()

def sha3_512_hash(password):
    """Generate SHA3-512 hash"""
    return hashlib.sha3_512(password.encode()).hexdigest()

def main():
    # Dictionary of available hash functions
    hash_functions = {
        1: ("MD5", md5_hash),
        2: ("SHA1", sha1_hash),
        3: ("SHA256", sha256_hash),
        4: ("SHA512", sha512_hash),
        5: ("BLAKE2b", blake2b_hash),
        6: ("BLAKE2s", blake2s_hash),
        7: ("bcrypt (recommended for passwords)", bcrypt_hash),
        8: ("PBKDF2 (recommended for passwords)", pbkdf2_hash),
        9: ("SHA3-256", sha3_256_hash),
        10: ("SHA3-512", sha3_512_hash)
    }
    
    print("=" * 50)
    print("         PASSWORD HASH GENERATOR")
    print("=" * 50)
    print("\nAvailable Hash Algorithms:")
    print("-" * 30)
    
    for num, (name, _) in hash_functions.items():
        print(f"{num}. {name}")
    
    print("-" * 30)
    
    try:
        choice = int(input("\nSelect hash algorithm (enter number): "))
        
        if choice not in hash_functions:
            print("Invalid choice! Please select a number from the list.")
            return
        
        algorithm_name, hash_function = hash_functions[choice]
        
        print(f"\nSelected: {algorithm_name}")
        
        # Get password securely (won't show on screen)
        password = getpass.getpass("Enter password to hash: ")
        
        if not password:
            print("Password cannot be empty!")
            return
        
        print("\nGenerating hash...")
        
        try:
            hash_result = hash_function(password)
            
            print("\n" + "=" * 50)
            print(f"Algorithm: {algorithm_name}")
            print(f"Hash: {hash_result}")
            print("=" * 50)
            
            # Security note for weak algorithms
            if choice in [1, 2]:  # MD5, SHA1
                print("\n⚠️  WARNING: This algorithm is considered cryptographically weak.")
                print("   For password storage, use bcrypt or PBKDF2 instead.")
            
        except Exception as e:
            print(f"Error generating hash: {e}")
            
    except ValueError:
        print("Invalid input! Please enter a number.")
    except KeyboardInterrupt:
        print("\n\nOperation cancelled.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
