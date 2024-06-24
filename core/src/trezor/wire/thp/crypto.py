from micropython import const
from trezorcrypto import aesgcm, bip32, curve25519, hmac

from storage import device
from trezor import utils
from trezor.crypto.hashlib import sha256

from apps.common.paths import HARDENED

PUBKEY_LENGTH = const(32)
if utils.DISABLE_ENCRYPTION:
    DUMMY_TAG = b"\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xB0\xB1\xB2\xB3\xB4\xB5"

if __debug__:
    from ubinascii import hexlify


def enc(buffer: utils.BufferType, key: bytes, nonce: int, auth_data: bytes) -> bytes:
    """
    Encrypts the provided `buffer` with AES-GCM (in place).
    Returns a 16-byte long encryption tag.
    """
    iv = _get_iv_from_nonce(nonce)
    aes_ctx = aesgcm(key, iv)
    aes_ctx.auth(auth_data)
    aes_ctx.encrypt_in_place(buffer)
    return aes_ctx.finish()


# @codescene(disable: "Excess Number of Function Arguments") # TODO remove before prod
def dec(
    buffer: utils.BufferType, tag: bytes, key: bytes, nonce: int, auth_data: bytes
) -> bool:
    """
    Decrypts the provided buffer (in place). Returns `True` if the provided authentication `tag` is the same as
    the tag computed in decryption, otherwise it returns `False`.
    """
    iv = _get_iv_from_nonce(nonce)
    aes_ctx = aesgcm(key, iv)
    aes_ctx.auth(auth_data)
    aes_ctx.decrypt_in_place(buffer)
    computed_tag = aes_ctx.finish()
    return computed_tag == tag


class BusyDecoder:
    def __init__(self, key: bytes, nonce: int, auth_data: bytes) -> None:
        iv = _get_iv_from_nonce(nonce)
        self.aes_ctx = aesgcm(key, iv)
        self.aes_ctx.auth(auth_data)

    def decrypt_part(self, part: utils.BufferType) -> None:
        self.aes_ctx.decrypt_in_place(part)

    def finish_and_check_tag(self, tag: bytes) -> bool:
        computed_tag = self.aes_ctx.finish()
        return computed_tag == tag


PROTOCOL_NAME = bytes("Noise_XX_25519_AESGCM_SHA256", "ascii")
IV_1 = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
IV_2 = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"


class Handshake:

    def __init__(self) -> None:
        self.trezor_ephemeral_privkey: bytes
        self.ck: bytes
        self.k: bytes
        self.h: bytes
        self.key_receive: bytes
        self.key_send: bytes

    def _handle_th1_crypto(
        self,
        device_properties: bytes,
        host_ephemeral_pubkey: bytes,
    ) -> tuple[bytes, bytes, bytes]:

        trezor_static_privkey, trezor_static_pubkey = self._derive_static_key_pair()
        if __debug__:
            trezor_static_privkey = b"\x67\x0c\x63\x18\x7b\x4d\x55\x6d\xf6\x06\xed\xce\x0f\x91\xad\xda\x09\xfb\x43\xc4\x99\x8c\x30\x97\xa8\x90\x80\xbe\x09\x05\xa7\x27"
            trezor_static_pubkey = b"\xcc\xbf\x52\x9f\xc8\xdd\x46\x62\xd4\xd1\xd1\xfa\x66\x36\x8b\x87\x58\xc0\xb6\x67\x3a\x1b\xb9\xd5\x32\xd9\x5c\xa6\x07\xcb\xf7\x29"
        # 1
        self.trezor_ephemeral_privkey = curve25519.generate_secret()
        trezor_ephemeral_pubkey = curve25519.publickey(self.trezor_ephemeral_privkey)
        # 2
        self.h = _hash_of_two(PROTOCOL_NAME, device_properties)
        # 3
        self.h = _hash_of_two(self.h, host_ephemeral_pubkey)
        # 4
        self.h = _hash_of_two(self.h, trezor_ephemeral_pubkey)

        # 5 - TODO rename `point`
        point = curve25519.multiply(
            self.trezor_ephemeral_privkey, host_ephemeral_pubkey
        )
        self.ck, self.k = _hkdf(PROTOCOL_NAME, point)
        # 6
        mask = _hash_of_two(trezor_static_pubkey, trezor_ephemeral_pubkey)
        # 7
        trezor_masked_static_pubkey = curve25519.multiply(mask, trezor_static_pubkey)
        # 8
        aes_ctx = aesgcm(self.k, IV_1)
        encrypted_trezor_static_pubkey = aes_ctx.encrypt(trezor_masked_static_pubkey)
        aes_ctx.auth(self.h)
        tag_to_encrypted_key = aes_ctx.finish()
        encrypted_trezor_static_pubkey = (
            encrypted_trezor_static_pubkey + tag_to_encrypted_key
        )
        # 9
        self.h = _hash_of_two(self.h, encrypted_trezor_static_pubkey)
        # 10 - TODO rename `point`
        point = curve25519.multiply(trezor_static_privkey, host_ephemeral_pubkey)
        self.ck, self.k = _hkdf(self.ck, curve25519.multiply(mask, point))
        # 11
        aes_ctx = aesgcm(self.k, IV_1)
        aes_ctx.auth(self.h)
        tag = aes_ctx.finish()
        # 12
        self.h = _hash_of_two(self.h, tag)
        # 13 -ish
        return (trezor_ephemeral_pubkey, encrypted_trezor_static_pubkey, tag)

    def _handle_th2_crypto(
        self,
        encrypted_host_static_pubkey: utils.BufferType,
        encrypted_payload: utils.BufferType,
    ):

        # 1a
        aes_ctx = aesgcm(self.k, IV_2)
        aes_ctx.auth(self.h)
        # 2
        self.h = _hash_of_two(self.h, encrypted_host_static_pubkey)
        # 1b
        aes_ctx.decrypt_in_place(
            memoryview(encrypted_host_static_pubkey)[:PUBKEY_LENGTH]
        )
        host_static_pubkey = memoryview(encrypted_host_static_pubkey)[:PUBKEY_LENGTH]
        tag = aes_ctx.finish()
        assert tag == encrypted_host_static_pubkey[-16:]
        # 3
        self.ck, self.k = _hkdf(
            self.ck,
            curve25519.multiply(self.trezor_ephemeral_privkey, host_static_pubkey),
        )
        # 4
        aes_ctx = aesgcm(self.k, IV_1)
        aes_ctx.auth(self.h)
        aes_ctx.decrypt_in_place(memoryview(encrypted_payload)[:-16])
        tag = aes_ctx.finish()
        assert tag == encrypted_payload[-16:]

        # 5 and #6 somewhere else
        # 7
        self.h = _hash_of_two(self.h, memoryview(encrypted_payload)[:-16])
        # 8 somewhere else
        # 9
        self.key_receive, self.key_send = _hkdf(self.ck, b"")

        # 10 somewhere else

    def _derive_static_key_pair(self) -> tuple[bytes, bytes]:
        node_int = HARDENED | int.from_bytes(b"\x00THP", "big")
        node = bip32.from_seed(device.get_device_secret(), "curve25519")
        node.derive(node_int)

        trezor_static_privkey = node.private_key()
        trezor_static_pubkey = node.public_key()[1:33]
        # Note: the first byte \x01 of the public key is removed

        return trezor_static_privkey, trezor_static_pubkey


def _hkdf(chaining_key, input: bytes):
    temp_key = hmac(hmac.SHA256, chaining_key, input).digest()
    output_1 = hmac(hmac.SHA256, temp_key, b"\x01").digest()
    ctx_output_2 = hmac(hmac.SHA256, temp_key, output_1)
    ctx_output_2.update(b"\x02")
    output_2 = ctx_output_2.digest()
    return (output_1, output_2)


def _hash_of_two(part_1: bytes, part_2: bytes) -> bytes:
    ctx = sha256(part_1)
    ctx.update(part_2)
    return ctx.digest()


def _get_iv_from_nonce(nonce: int) -> bytes:
    utils.ensure(
        nonce <= 0xFFFFFFFFFFFFFFFF, "Nonce overflow, terminate the channel"
    )  # TODO change to different error?
    return bytes(4) + nonce.to_bytes(8, "big")
