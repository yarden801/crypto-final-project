from dataclasses import dataclass
from datetime import datetime
from typing import Optional
import base64


@dataclass
class Certificate:
    serial: str
    subject_cn: str
    issuer_cn: str
    not_before: datetime
    not_after: datetime
    subject_pub_pem: bytes
    signature: Optional[bytes] = None

    def to_tbs(self) -> bytes:
        """Return to-be-signed bytes (all fields except signature)."""
        return b"|".join([
            self.serial.encode(),
            self.subject_cn.encode(),
            self.issuer_cn.encode(),
            str(int(self.not_before.timestamp())).encode(),
            str(int(self.not_after.timestamp())).encode(),
            self.subject_pub_pem,
        ])

    def to_pem(self) -> bytes:
        """Export certificate in a simple ad-hoc PEM-like format."""
        body = base64.b64encode(self.to_tbs() + b"||SIG||" + (self.signature or b""))
        return (
            b"-----BEGIN THRESH-CA CERT-----\n"
            + body
            + b"\n-----END THRESH-CA CERT-----\n"
        )

    @staticmethod
    def from_pem(pem: bytes) -> "Certificate":
        """Parse a Certificate from the ad-hoc PEM format."""
        body = pem.splitlines()[1]
        raw = base64.b64decode(body)
        tbs, sig = raw.split(b"||SIG||", 1)
        serial, subject_cn, issuer_cn, nbf, naf, pub = tbs.split(b"|")
        return Certificate(
            serial=serial.decode(),
            subject_cn=subject_cn.decode(),
            issuer_cn=issuer_cn.decode(),
            not_before=datetime.fromtimestamp(int(nbf)),
            not_after=datetime.fromtimestamp(int(naf)),
            subject_pub_pem=pub,
            signature=sig,
        )
