"""A software WebAuthn authenticator for tests.

Builds the same messages a real security key or passkey would, signed with a real
P-256 key, so the server's verification code runs for real. It also lets tests do what
a browser never will: sign for the wrong site, or move the counter backwards.
"""
import hashlib
import json
import os
import struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

UP, UV, AT = 0x01, 0x04, 0x40  # flags: user present, user verified, attested credential data


class SoftKey:
    def __init__(self, rp_id="localhost", origin="http://localhost:8000"):
        self.private = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(16)
        self.sign_count = 0
        self.rp_id = rp_id
        self.origin = origin

    def _cose_public_key(self) -> bytes:
        n = self.private.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1,
                            -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})

    def _client_data(self, kind, challenge, origin) -> bytes:
        return json.dumps({"type": kind, "challenge": challenge,
                           "origin": origin or self.origin, "crossOrigin": False}).encode()

    def register(self, options: dict, origin=None) -> dict:
        client_data = self._client_data("webauthn.create", options["challenge"], origin)
        auth_data = (
            hashlib.sha256(self.rp_id.encode()).digest()
            + bytes([UP | UV | AT]) + struct.pack(">I", self.sign_count)
            + bytes(16)                                         # AAGUID: none
            + struct.pack(">H", len(self.credential_id)) + self.credential_id
            + self._cose_public_key()
        )
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        cid = bytes_to_base64url(self.credential_id)
        return {"id": cid, "rawId": cid, "type": "public-key",
                "response": {"clientDataJSON": bytes_to_base64url(client_data),
                             "attestationObject": bytes_to_base64url(attestation)},
                "clientExtensionResults": {}}

    def authenticate(self, options: dict, origin=None, sign_count=None, signer=None) -> dict:
        self.sign_count = self.sign_count + 1 if sign_count is None else sign_count
        client_data = self._client_data("webauthn.get", options["challenge"], origin)
        auth_data = (hashlib.sha256(self.rp_id.encode()).digest()
                     + bytes([UP | UV]) + struct.pack(">I", self.sign_count))
        signed = auth_data + hashlib.sha256(client_data).digest()
        signature = (signer or self.private).sign(signed, ec.ECDSA(hashes.SHA256()))
        cid = bytes_to_base64url(self.credential_id)
        return {"id": cid, "rawId": cid, "type": "public-key",
                "response": {"clientDataJSON": bytes_to_base64url(client_data),
                             "authenticatorData": bytes_to_base64url(auth_data),
                             "signature": bytes_to_base64url(signature)},
                "clientExtensionResults": {}}
