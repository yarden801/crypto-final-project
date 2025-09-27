# =============================
# common/crypto_utils.py
# =============================
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend




def gen_rsa_keypair(bits=2048):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=default_backend())
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem




def load_private_key(pem: bytes):
    return serialization.load_pem_private_key(pem, password=None)




def sign(priv_pem: bytes, data: bytes) -> bytes:
    priv = load_private_key(priv_pem)
    return priv.sign(data, padding.PKCS1v15(), hashes.SHA256())




def verify(pub_pem: bytes, data: bytes, sig: bytes) -> bool:
    pub = serialization.load_pem_public_key(pub_pem)
    try:
        pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False