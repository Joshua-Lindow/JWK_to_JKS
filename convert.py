import json
import base64
import sys
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def base64url_decode(input):
    input += '=' * (4 - (len(input) % 4))
    return base64.urlsafe_b64decode(input)

def int_from_bytes(b):
    return int.from_bytes(b, 'big')

def jwk_to_pem(jwk_file, pem_file):
    with open(jwk_file, 'r') as file:
        jwk = json.load(file)

    # Extract the components
    n = int_from_bytes(base64url_decode(jwk['n']))
    e = int_from_bytes(base64url_decode(jwk['e']))
    d = int_from_bytes(base64url_decode(jwk['d']))
    p = int_from_bytes(base64url_decode(jwk['p']))
    q = int_from_bytes(base64url_decode(jwk['q']))
    dp = int_from_bytes(base64url_decode(jwk['dp']))
    dq = int_from_bytes(base64url_decode(jwk['dq']))
    qi = int_from_bytes(base64url_decode(jwk['qi']))

    # Create the RSA private key
    private_key = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=dp,
        dmq1=dq,
        iqmp=qi,
        public_numbers=rsa.RSAPublicNumbers(
            e=e,
            n=n
        )
    ).private_key()

    # Serialize the key to PEM format
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Write the PEM to a file
    with open(pem_file, 'wb') as file:
        file.write(pem)

    print(f"PEM file created: {pem_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python jwk_to_pem.py <input_jwk_file> <output_pem_file>")
        sys.exit(1)

    jwk_file = sys.argv[1]
    pem_file = sys.argv[2]
    jwk_to_pem(jwk_file, pem_file)
