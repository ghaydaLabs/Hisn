import hashlib
import re
import string
import random
import math
import requests

# Constants for password complexity checks
MIN_LENGTH = 12
UPPERCASE_CHARS = string.ascii_uppercase
LOWERCASE_CHARS = string.ascii_lowercase
DIGITS = string.digits
SPECIAL_CHARS = string.punctuation # Includes common symbols

# ====================================================================
# 1. Password Strength and Complexity Analysis
# ====================================================================

def check_strength(password: str) -> tuple[int, list[str]]:
    """
    Analyzes password complexity and assigns a score (0-4) based on security criteria.
    
    The criteria are:
    1. Length (>= MIN_LENGTH)
    2. Inclusion of uppercase letters
    3. Inclusion of digits
    4. Inclusion of special characters
    
    Args:
        password: The string to be analyzed.
        
    Returns:
        A tuple containing:
        - score (int): The complexity score (0-4).
        - missing_criteria (list[str]): List of missing criteria in English for feedback.
    """
    score = 0
    missing_criteria = []

    # Criteria 1: Length Check
    if len(password) >= MIN_LENGTH:
        score += 1
    else:
        # English reason expected by app.py
        missing_criteria.append("Increase length to at least 12 characters")

    # Criteria 2-4: Character Type Checks
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        missing_criteria.append("Add uppercase letters (A-Z)")

    if re.search(r'\d', password):
        score += 1
    else:
        missing_criteria.append("Add digits (0-9)")

    if re.search(r'[^A-Za-z0-9\s]', password): # Search for any non-alphanumeric/non-space
        score += 1
    else:
        missing_criteria.append("Add special symbols (e.g., !@#$)")

    return score, missing_criteria

# ====================================================================
# 2. Entropy Calculation (Measures randomness and crack time)
# ====================================================================

def calculate_entropy(password: str) -> float:
    """
    Calculates the Shannon Entropy (in bits) of a password.
    Entropy = N * log2(L)
    Where N is the length of the password and L is the size of the character set used.

    Args:
        password: The password string.

    Returns:
        entropy (float): The entropy value in bits.
    """
    N = len(password)
    
    # Calculate the size of the character set (L) based on present characters
    L = 0
    
    if re.search(r'[a-z]', password): L += len(LOWERCASE_CHARS) # 26
    if re.search(r'[A-Z]', password): L += len(UPPERCASE_CHARS) # 26
    if re.search(r'\d', password): L += len(DIGITS)             # 10
    if re.search(r'[^A-Za-z0-9\s]', password): L += len(SPECIAL_CHARS) # ~32+

    if L == 0 or N == 0:
        return 0.0

    # Calculate entropy using the formula: N * log2(L)
    # math.log2 is log base 2
    entropy = N * math.log2(L) if L > 0 else 0.0
    
    return round(entropy, 2)

# ====================================================================
# 3. Password Breach Check (HIBP API)
# ====================================================================

def check_pwned(password: str) -> tuple[str, int]:
    """
    Checks if a password has been compromised using the 'Have I Been Pwned' API 
    (k-anonymity method).
    
    Args:
        password: The password string to check.
        
    Returns:
        A tuple containing:
        - breach_status (str): "Safe", "Breached", or "API Error".
        - breach_count (int): Number of times the password was found (0 if safe).
    """
    try:
        # 1. Hash the password using SHA-1
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        
        # 2. Split the hash into prefix and suffix
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        # 3. Query the HIBP API using the prefix
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        # Setting a timeout for safety
        response = requests.get(url, timeout=5) 

        if response.status_code == 200:
            # 4. Search the response for the suffix
            for line in response.text.splitlines():
                # HIBP response format: Suffix:Count
                found_suffix, count = line.split(':')
                if found_suffix == suffix:
                    return "Breached", int(count)
            
            return "Safe", 0
        
        elif response.status_code == 404:
            # Prefix not found, therefore safe
            return "Safe", 0
        
        else:
            # Handle API limits or other HTTP errors
            return "API Error", 0

    except requests.exceptions.RequestException:
        # Network or timeout error
        return "API Error", 0
    except Exception:
        # Other unexpected errors
        return "API Error", 0


# ====================================================================
# 4. Secure Password Generation
# ====================================================================

def generate_password(length: int = 16) -> str:
    """
    Generates a cryptographically secure random password ensuring complexity 
    (at least one of each required character type) for maximum strength.
    
    Args:
        length: The desired length of the password (default is 16).
        
    Returns:
        A strong, randomly generated password string.
    """
    # 1. Define all possible characters
    all_chars = UPPERCASE_CHARS + LOWERCASE_CHARS + DIGITS + SPECIAL_CHARS
    
    # 2. Ensure at least one of each required type (minimum 4 chars used here)
    if length < 4:
        # Fallback for very short length
        length = 4 

    password_parts = [
        random.choice(UPPERCASE_CHARS),
        random.choice(LOWERCASE_CHARS),
        random.choice(DIGITS),
        random.choice(SPECIAL_CHARS)
    ]
    
    # 3. Fill the rest of the length with random characters
    remaining_length = length - len(password_parts)
    password_parts.extend(random.choices(all_chars, k=remaining_length))
    
    # 4. Shuffle the parts to prevent predictable patterns (e.g., A1!a...)
    random.shuffle(password_parts)
    
    return "".join(password_parts)


# ====================================================================
# 5. Hash Analysis and Identification
# ====================================================================

def analyze_hash(hash_value: str) -> tuple[str, str, str]:
    """
    Analyzes a hash string to determine its likely type based on length and pattern.
    
    Args:
        hash_value: The hash string to analyze.
        
    Returns:
        A tuple containing (3 values):
        - hash_type (str): The identified hash algorithm (e.g., MD5, SHA-256).
        - recommendations (str): Security advice for the given hash type.
        - strength (str): A qualitative assessment (e.g., Weak, Strong).
    """
    hash_len = len(hash_value)
    
    # Normalize the hash (remove leading/trailing whitespace, ensure hex characters)
    hash_value = hash_value.strip()

    # Define common hash patterns based on hexadecimal length
    # Note: Recommendations are kept concise and actionable
    hash_patterns = {
        32: ("MD5 / MD4 / NTLM", "Weak", "Extremely weak due to collision and speed. Recommendation: Migrate immediately to Argon2 or bcrypt. Never store passwords with this hash."),
        40: ("SHA-1 / MySQL5", "Moderate", "Considered deprecated for security purposes (vulnerable to collision attacks). Recommendation: Stop using SHA-1 for password storage. Use SHA-256 for integrity checks only."),
        56: ("SHA-224", "Moderate", "A reasonably secure hash, but not as widely recommended as SHA-256/512. Recommendation: Transition to SHA-256 or a dedicated Key Derivation Function (KDF)."),
        64: ("SHA-256", "Strong", "Currently considered cryptographically strong for general hashing. Recommendation: Ensure salt is used and consider migrating to a dedicated KDF for password storage (Argon2/bcrypt)."),
        96: ("SHA-384", "Strong", "A secure variant of SHA-2.Recommendation: Similar to SHA-256; ensure proper usage with salting for password storage."),
        128: ("SHA-512", "Strong", "One of the strongest general-purpose hashes available. Recommendation: Best suited for verifying large file integrity or as part of a robust KDF."),
    }

    # Check for specific KDF patterns first (often contain non-hex chars)
    if hash_value.startswith('$2a$') or hash_value.startswith('$2b$') or hash_value.startswith('$2y$'):
        return "bcrypt", "Excellent", "bcrypt is a highly recommended KDF. It is slow and uses salt, making brute-force attacks expensive. Recommendation: Ensure the cost factor (e.g., $10$ in $2a$10$) is sufficiently high (currently >= 12)."
    if hash_value.startswith('$argon2id$') or hash_value.startswith('$argon2i$'):
        return "Argon2 (ID/I)", "Excellent", "Argon2 is the current winner of the PHC and is highly secure. Recommendation: Ensure all memory, time, and parallelism settings are correctly configured."

    # Check for standard hexadecimal hashes based on length
    if hash_len in hash_patterns and re.match(r'^[0-9a-fA-F]+$', hash_value):
        return hash_patterns[hash_len]

    # If no match is found
    return "Unknown/Malformed", "Unknown", "The length or format does not match any common hash type (e.g., MD5, SHA-256). It might be incomplete, malformed, or a custom obfuscation scheme. Recommendation: Re-verify the input hash or investigate the custom hashing implementation."
