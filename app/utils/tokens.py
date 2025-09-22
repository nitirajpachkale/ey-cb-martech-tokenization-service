from typing import Dict
import hashlib
import base64

# Utility function to generate irreversible token
def generate_irreversible_token(val: str) -> str:
    hash_obj = hashlib.sha256(val.encode('utf-8'))
    return base64.urlsafe_b64encode(hash_obj.digest()).decode('utf-8')

# Function to create a tokenized dictionary from PII data
def generate_tokenized_dict(pii_data: Dict[str, str]) -> Dict[str, str]:
    tokenized_data = {}
    for field, value in pii_data.items():
        tokenized_data[field] = generate_irreversible_token(value)
    return tokenized_data