from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()
message = input("Enter the message you want to sign: ").encode()
digest = hashes.Hash(hashes.SHA256())
digest.update(message)
hash_value = digest.finalize()
print("\nSHA-256 Hash:", hash_value.hex())
signature = private_key.sign(hash_value, ec.ECDSA(hashes.SHA256()))
print("\nDigital Signature:", signature.hex())
try:
    public_key.verify(signature, hash_value, ec.ECDSA(hashes.SHA256()))
    print("\nSignature is valid!")
except InvalidSignature:
    print("\nInvalid signature!")
