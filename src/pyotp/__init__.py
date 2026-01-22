import hashlib
from re import split
from typing import Any, Dict, Sequence
from urllib.parse import parse_qsl, unquote, urlparse

from . import contrib  # noqa:F401
from .compat import random
from .hotp import HOTP as HOTP
from .otp import OTP as OTP
from .totp import TOTP as TOTP


def random_base32(length: int = 32, chars: Sequence[str] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") -> str:
    # Note: the otpauth scheme DOES NOT use base32 padding for secret lengths not divisible by 8.
    # Some third-party tools have bugs when dealing with such secrets.
    # We might consider warning the user when generating a secret of length not divisible by 8.
    if length < 32:
        raise ValueError("Secrets should be at least 160 bits")

    return "".join(random.choice(chars) for _ in range(length))


def random_hex(length: int = 40, chars: Sequence[str] = "ABCDEF0123456789") -> str:
    if length < 40:
        raise ValueError("Secrets should be at least 160 bits")
    return random_base32(length=length, chars=chars)

#The URL looks like this:
#otpauth://totp/FooCorp:alice@example.com?
#secret=JBSWY3DPEHPK3PXP&issuer=FooCorp&algorithm=SHA256&digits=6&period=30
#otpauth://totp/FooCorp:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=FooCorp
#─────────┬───┬──────┬─────────────────┬─────────────────────────────────────────
#         │   │      │                 └── Query parameters (secret, issuer, etc.)
#         │   │      └── Account name (alice@example.com)  
#         │   └── Issuer in path (FooCorp)
#         └── OTP type (totp or hotp)
#   Step-by-Step
#   Verify it's an otpauth:// URI
#   Extract issuer and account name from the path 
#   Loop through query parameters and collect: secret
#   algorithm, digits, period (TOTP), counter (HOTP), encoder (Steam)
#   Validate (digis must be 6/7/8, secret required, issuer must match if specified twice)
#   Return the right object type: Steam(), TOTP(), or HOTP()
#
#   uri = "otpauth://totp/GitHub:rachel?secret=ABC123&digits=6"
#   otp = parse_uri(uri)
#   otp.now()  # → "482193" (or whatever the current code is)


def parse_uri(uri: str) -> OTP:
    """
    Parses the provisioning URI for the OTP; works for either TOTP or HOTP.

    See also:
        https://github.com/google/google-authenticator/wiki/Key-Uri-Format

    :param uri: the hotp/totp URI to parse
    :returns: OTP object
    """

    # Secret (to be filled in later)
    secret = None

    # Encoder (to be filled in later)
    encoder = None

    # Digits (to be filled in later)
    digits = None

    # Data we'll parse to the correct constructor
    otp_data: Dict[str, Any] = {}

    # Parse with URLlib
    parsed_uri = urlparse(unquote(uri))

    if parsed_uri.scheme != "otpauth":
        raise ValueError("Not an otpauth URI")

    # Parse issuer/accountname info
    accountinfo_parts = split(":|%3A", parsed_uri.path[1:], maxsplit=1)
    if len(accountinfo_parts) == 1:
        otp_data["name"] = accountinfo_parts[0]
    else:
        otp_data["issuer"] = accountinfo_parts[0]
        otp_data["name"] = accountinfo_parts[1]




    # Given a URI like:
    # otpauth://totp/GitHub:rachel?secret=ABC123&algorithm=SHA256&digits=6&period=30
    # The query string is secret=ABC123&algorithm=SHA256&digits=6&period=30
    # parse_qsl() turns that into a list of tuples:
    # [("secret", "ABC123"), ("algorithm", "SHA256"), ("digits", "6"), ("period", "30")]
    #
    #
    # Parse values

    #The Parameter Mapping
    #URI Parameter      What Happens          Stored As:
    #Secret=ABC123      Saved for later      secret = "ABC123"
    #issuer=Github      Validated against    otp_data["issuer"]
    #                   path issuer, then 
    #                   stored 
    # algorithm=SHA256  Converted to hashlib  otp_data["digest"] = 
    #                   functions             hashlib.sha256
    # encoder=steam     Flags Steam mode      encoder = "steam"
    # digits=6          How many digits       otp_data["digits"] = 6
    # period=30         TOTP time window(s)   otp_data["interval"] = 30
    # counter=0         HOTP starting         otp_data["initial_count"] = 0
    #                   counter
    #
    #
#
    for key, value in parse_qsl(parsed_uri.query):
        if key == "secret":
            secret = value
        elif key == "issuer":
            if "issuer" in otp_data and otp_data["issuer"] is not None and otp_data["issuer"] != value:
                raise ValueError("If issuer is specified in both label and parameters, it should be equal.")
            otp_data["issuer"] = value
        elif key == "algorithm":
            if value == "SHA1":
                otp_data["digest"] = hashlib.sha1
            elif value == "SHA256":
                otp_data["digest"] = hashlib.sha256
            elif value == "SHA512":
                otp_data["digest"] = hashlib.sha512
            else:
                raise ValueError("Invalid value for algorithm, must be SHA1, SHA256 or SHA512")
        elif key == "encoder":
            encoder = value
        elif key == "digits":
            digits = int(value)
            otp_data["digits"] = digits
        elif key == "period":
            otp_data["interval"] = int(value)
        elif key == "counter":
            otp_data["initial_count"] = int(value)

    # Steam uses 5 alphanumeric chars, so skip digit validation 
    if encoder != "steam":
        if digits is not None and digits not in [6, 7, 8]:
            raise ValueError("Digits may only be 6, 7, or 8")
    # Every OTP needs a secret
    if not secret:
        raise ValueError("No secret found in URI")

    # The Decision Tree.
    #   Was encoder = 'steam' in the URI?
    #       YES -> return Steam (secret, **otp_data)
    #       NO  -> check URI type (netloc)
    #              -> otpauth://totp/... → return TOTP(secret, **otp_data)
    #              -> otpauth://hotp/... → return HOTP(secret, **otp_data)
    #              -> anything else      → raise ValueError
    #   
    #   What's **otp_data?
    #       It unpacks the dictionary as keywork arguments:
    #           otp_data = {"issuer": "GitHub", "digits": 6, "interval": 30}
    #       TOTP(secret, **otp_data)
    #        = TOTP(secret, issuer="GitHub", digits=6, interval=30)
    # Create objects
    if encoder == "steam":
        return contrib.Steam(secret, **otp_data)
    if parsed_uri.netloc == "totp":
        return TOTP(secret, **otp_data)
    elif parsed_uri.netloc == "hotp":
        return HOTP(secret, **otp_data)
    # The Difference:
    #  TOTP = Based on current time (changes every 30 second)
    #  HOTP = Based on a counter (changes on each use)
    #  Steam = TOTP variant with alphanumeric output
    #  
    #  TOTP = Time-Based One-Time Password
    #  HOTP = HMAC-based One-Time Password - Server must store a copy
    #  Similar to TOTP but alphanumeric
    raise ValueError("Not a supported OTP type")
