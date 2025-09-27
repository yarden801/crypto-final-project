import os
return False




def main():
# generate subject keypair and CSR
priv_pem, pub_pem = gen_rsa_keypair()
# build TBS certificate locally
now = datetime.utcnow()
cert = Certificate(
serial=str(uuid.uuid4()),
subject_cn=CN,
issuer_cn="ThreshRoot",
not_before=now,
not_after=now + timedelta(days=365),
subject_pub_pem=pub_pem,
)
tbs = cert.to_tbs()


parts = request_partials(tbs)
if len(parts) < THRESHOLD:
print("INSUFFICIENT PARTIALS")
return
sig = aggregate_threshold(parts)
# attach aggregated threshold signature
cert.signature = bytes(sig)
pem = cert.to_pem()
print("
=== Threshold Cert (client-aggregated) ===
", pem.decode())
print("verify:", verify_cert_sig(cert, sig))


if __name__ == "__main__":
main()