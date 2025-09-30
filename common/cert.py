from dataclasses import dataclass
from datetime import datetime
from typing import Optional
import base64


@dataclass
class Certificate:
    def __init__(self, serial, subject_cn, issuer_cn,
                 not_before, not_after, subject_pub_pem,
                 signature=None, is_ca=False):
        self.serial = serial
        self.subject_cn = subject_cn
        self.issuer_cn = issuer_cn
        self.not_before = not_before
        self.not_after = not_after
        self.subject_pub_pem = subject_pub_pem
        self.signature = signature
        self.is_ca = is_ca   

    def to_tbs(self) -> bytes:
        return b"|".join([
            self.serial.encode(),
            self.subject_cn.encode(),
            self.issuer_cn.encode(),
            str(int(self.not_before.timestamp())).encode(),
            str(int(self.not_after.timestamp())).encode(),
            self.subject_pub_pem,
            b"CA" if self.is_ca else b"EE"  # encode CA flag
        ])

    def to_pem(self, chain: list = None) -> bytes:
        """Export certificate in PEM-like format, optionally with a chain appended."""
        body = base64.b64encode(self.to_tbs() + b"||SIG||" + (self.signature or b""))
        pem = (
            b"-----BEGIN THRESH-CA CERT-----\n"
            + body
            + b"\n-----END THRESH-CA CERT-----\n"
        )
        if chain:
            if isinstance(chain, list):
                for c in chain:
                    pem += b"\n" + c.to_pem()
            else:
                pem += b"\n" + chain.to_pem()
        return pem

    @staticmethod
    def from_pem(pem: bytes) -> list["Certificate"]:
        """Parse one or more Certificates from concatenated PEM blocks."""
        certs = []
        blocks = pem.split(b"-----BEGIN THRESH-CA CERT-----")
        for b in blocks:
            if not b.strip():
                continue
            body = b.split(b"-----END THRESH-CA CERT-----")[0].strip()
            raw = base64.b64decode(body)
            tbs, sig = raw.split(b"||SIG||", 1)
            serial, subject_cn, issuer_cn, nbf, naf, pub, ca_flag  = tbs.split(b"|")
            is_ca = (ca_flag == b"CA")
            certs.append(Certificate(
                serial=serial.decode(),
                subject_cn=subject_cn.decode(),
                issuer_cn=issuer_cn.decode(),
                not_before=datetime.fromtimestamp(int(nbf)),
                not_after=datetime.fromtimestamp(int(naf)),
                subject_pub_pem=pub,
                signature=sig,
                is_ca=is_ca
            ))
        return certs
