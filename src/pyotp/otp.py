import base64
import hashlib
import hmac
from typing import Any, Optional

#OTP (base class)

class OTP(object):
    """
    Base class for OTP handlers.
    """

    def __init__(
        self,
        s: str,
        digits: int = 6,
        digest: Any = hashlib.sha1,
        name: Optional[str] = None,
        issuer: Optional[str] = None,
    ) -> None:
        # Just stores the configuration
        self.digits = digits
        if digits > 10:
            raise ValueError("digits must be no greater than 10")
        self.digest = digest
        if digest in [hashlib.md5, hashlib.shake_128]:
            raise ValueError("selected digest function must generate digest size greater than or equals to 18 bytes")
        self.secret = s
        self.name = name or "Secret"
        #Account Name
        self.issuer = issuer

    def generate_otp(self, input: int) -> str:
        """
        :param input: the HMAC counter value to use as the OTP input.
            Usually either the counter, or the computed integer based on the Unix timestamp
        """
        # Implements RFC 4226

        if input < 0:
            raise ValueError("input must be positive integer")
        hasher = hmac.new(self.byte_secret(), self.int_to_bytestring(input), self.digest)
        # byte_scret and int_to_bytestring called here to satisify
        # the requirements of hmac: hmac.new(key, message, hash_function)
        #
        if hasher.digest_size < 18:
            raise ValueError("digest size is lower than 18 bytes, which will trigger error on otp generation")
        hmac_hash = bytearray(hasher.digest())
        offset = hmac_hash[-1] & 0xF
        code = (
            (hmac_hash[offset] & 0x7F) << 24
            | (hmac_hash[offset + 1] & 0xFF) << 16
            | (hmac_hash[offset + 2] & 0xFF) << 8
            | (hmac_hash[offset + 3] & 0xFF)
        )
        # Create HMAC mash
        # Dynamic Truncation -> Uses the last nibble of hash to pick a starting position
        # Extract 4 bytes as integer 
        # Grabs four consecutive bytes and combines them into 31 bit integer
        str_code = str(10_000_000_000 + (code % 10**self.digits))
        # code = 38472956 
        # code % 10 ** 6 = 472956
        # Add padding trick = 10000472956 
        # Take last 6 
        # This trick ensures the leading zeros are preserved.
        return str_code[-self.digits :]

    def byte_secret(self) -> bytes:
        # "JBSWY3DPEHPK3PXP" → b"Hello!\xde\xad\xbe\xef..."
        # "this specific secret happens to decode to bytes "hello" "
        # Base32 decode is a way to represent binary data to human readable data,
        # then you can put them as raw bytes again.
        # HMAC wants a message.
        secret = self.secret
        missing_padding = len(secret) % 8
        if missing_padding != 0:
            secret += "=" * (8 - missing_padding)
        return base64.b32decode(secret, casefold=True)
        # What This Method Does:
        # Converts a base32-encoded secret string into raw bytes 
        # The Padding Problem: Base32 requires input length to be mutiple of 8.
        # If secret is missing a byte, you add one to the secret
    @staticmethod
    def int_to_bytestring(i: int, padding: int = 8) -> bytes:
        """
        Turns an integer to the OATH specified
        bytestring, which is fed to the HMAC
        along with the secret
        """
        # Why Is This Needed?
        # HMAC takes bytes as input, not integers, this is taking numbers 
        # and converting them into bytes
        # Get Lowest 8 bites 
        # Shift right by 8 bits
        result = bytearray()
        while i != 0:
            result.append(i & 0xFF) # Keep only the leftmost 8 bits,
            i >>= 8                 # we shift, go to the next 8 bits 
        #12345 in binary:     00110000 00111001
        #0xFF in binary:      00000000 11111111
        #                    ─────────────────
        #AND result:          00000000 00111001  = 57 = 0x39
        #After:   00000000 00110000  (48 = 0x30)
        #result = 0x3930(reversed)
        
        # It's necessary to convert the final result from bytearray to bytes
        # because the hmac functions in python 2.6 and 3.3 don't work with
        # bytearray
        return bytes(bytearray(reversed(result)).rjust(padding, b"\0"))
        # bytes - immutable (can't change) - b = b'\x00\x01\x02'
        # bytearray - bytearray([0, 1, 2])
        # if i = 12345 (which is 0x3039 in hex):
        #   After the while loop:
        #   result = bytearray([0x39, 0x30])
        #   If we did return bytes(result):
        #       (wrong order, only two bytes)
        #   Reverse it (correct order)
        #   Pad to 8 bytes:
        #       .rjust(8, b"\0")  # → bytearray([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x39])
        #   Convert to bytes bytes(everything)
        
        # The while (reversed)loop extracts bytes backwards (least significant first)
        # For example, 0x3930 = 12345, but HMAC want an order such that 0x3039

# Input (counter or time)
#       int_to_bytestring() -> 8 bytes (padded with zeros)
#           HMAC-SHA1 (secret, input) -> 20 bytes of hash
#               Dynamic truncation:
#                       - Last byte tells us where to start (offset 0-15)
#                       - Grab 4 bytes starting here
#                       - Combine into one 31-bit integer
#               Modulor 10^6    -> 6-digit number
# 8 byte padding is for input to HMAC, not the output.
#
# offset = hmac_hash[19] & 0xF  # 0x5a & 0xF = 10
# `& 0xF` keeps only the last 4 bits, giving a value 0-15.
# Offset = 10, so grab bytes at index 10, 11, 12, 13:
# [0x1f, 0x86, 0x98, 0x69, 0x0e, 0x02, 0xca, 0x16, 0x61, 0x85, 0x50, 0xef, 0x7f, 0x19, 0xda, 0x8e, 0x94, 0x5b, 0x55, 0x5a]
#                                                               ↑     ↑     ↑     ↑
#                                                              [10]  [11]  [12]  [13]
#                                                              0x50  0xef  0x7f  0x19
# code = (
#    (0x50 & 0x7F) << 24  # Drop top bit, move to position 4
#  | (0xef & 0xFF) << 16  # Move to position 3
#  | (0x7f & 0xFF) << 8   # Move to position 2
#  | (0x19 & 0xFF)        # Move to position 1
# )
# Visual:
# Byte 1:  0x50      → 0x50 << 24 → 0x50000000
# Byte 2:  0xef      → 0xef << 16 →     0xef0000
# Byte 3:  0x7f      → 0x7f << 8  →         0x7f00
# Byte 4:  0x19      → 0x19       →             0x19
#                                  ──────────────────
# Combined with |                   0x50ef7f19
# The `|` (OR) combines them because they don't overlap:
# 0x50000000   =  01010000 00000000 00000000 00000000
# 0x00ef0000   =  00000000 11101111 00000000 00000000
# 0x00007f00   =  00000000 00000000 01111111 00000000
# 0x00000019   =  00000000 00000000 00000000 00011001
# ─────────────────────────────────────────────────────
# OR together  =  01010000 11101111 01111111 00011001
## How `& 0x7F` Drops a Bit
# 0x50 in binary:  01010000
# 0x7F in binary:  01111111  (mask)
# 0x50 & 0x7F   =  01010000  (same in this case)
# But if first byte were 0xFF:
# 0xFF in binary:  11111111
# 0x7F in binary:  01111111  (mask)
#                 ────────
# 0xFF & 0x7F   =  01111111  ← top bit forced to 0

# `0x7F` = `01111111` masks off the highest bit, ensuring the result is always positive (31 bits max instead of 32).

# Summary 
# They took four bytes together so they form into one integer
# In other words, they had HMAC-SHA1(secret, counter) -> 20 bytes (deterministic)
# Took out 4 bytes -> Combines into 31 bit integer 
# Modulo 10^6 -> 6 digit string like 482193