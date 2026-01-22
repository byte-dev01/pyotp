import unicodedata
from hmac import compare_digest
from typing import Dict, Optional, Union
from urllib.parse import quote, urlencode, urlparse


def build_uri(
    secret: str,
    name: str,
    initial_count: Optional[int] = None,
    issuer: Optional[str] = None,
    algorithm: Optional[str] = None,
    digits: Optional[int] = None,
    period: Optional[int] = None,
    **kwargs,
) -> str:
    # -> "otpauth://totp/GitHub:alice%40gmail.com?secret=ABC123&issuer=GitHub"
    """
    Returns the provisioning URI for the OTP; works for either TOTP or HOTP.

    This can then be encoded in a QR Code and used to provision the Google
    Authenticator app.

    For module-internal use.

    See also:
        https://github.com/google/google-authenticator/wiki/Key-Uri-Format

    :param secret: the hotp/totp secret used to generate the URI
    :param name: name of the account
    :param initial_count: starting counter value, defaults to None.
        If none, the OTP type will be assumed as TOTP.
    :param issuer: the name of the OTP issuer; this will be the
        organization title of the OTP entry in Authenticator
    :param algorithm: the algorithm used in the OTP generation.
    :param digits: the length of the OTP generated code.
    :param period: the number of seconds the OTP generator is set to
        expire every code.
    :param kwargs: other query string parameters to include in the URI
    :returns: provisioning uri
    """

    # initial_count may be 0 as a valid param
    is_initial_count_present = initial_count is not None
    #If you pass a counter -> HOTP. No Counter -> TOTP.

    # Handling values different from defaults
    is_algorithm_set = algorithm is not None and algorithm != "sha1"
    is_digits_set = digits is not None and digits != 6
    is_period_set = period is not None and period != 30
    #Only include non-default values in the URI to keep it short.

    otp_type = "hotp" if is_initial_count_present else "totp"
    # Has counter -> "hotp"
    # No counter -> "totp"
    base_uri = "otpauth://{0}/{1}?{2}"
    #                      ↑   ↑   ↑
    #                   type/label/query_string
    url_args: Dict[str, Union[None, int, str]] = {"secret": secret}
    # Creating a dictionary with the secret in it.
    # Starts with just the secret. Other parameters get added later if they are non-default

    label = quote(name)
    if issuer is not None:
        label = quote(issuer) + ":" + label
        url_args["issuer"] = issuer

    if is_initial_count_present:
        url_args["counter"] = initial_count
        # If HOTP, add counter
    if is_algorithm_set:
        url_args["algorithm"] = algorithm.upper()  # type: ignore
        # SHA-256. SHA-512
    if is_digits_set:
        url_args["digits"] = digits
        # 7 or 8
    if is_period_set:
        url_args["period"] = period
        # non-30 second intervals 
    for k, v in kwargs.items():
        if not isinstance(v, str):
            raise ValueError("All otpauth uri parameters must be strings")
        if k == "image":
            image_uri = urlparse(v)
            if image_uri.scheme != "https" or not image_uri.netloc or not image_uri.path:
                raise ValueError("{} is not a valid url".format(image_uri))
        url_args[k] = v
    # Adding Parameters 
    # Start: {"secret": "ABC123"}
    # After Counter -> Algorithm -> Digits: 
    # {"secret": "ABC123", "counter": 0, "algorithm": "SHA256", "digits": 8}
    # Allows passing extra parameters like image (logo for authenticator apps)
    # | Image URL | Valid? |
    #   |-----------|--------|
    #   | `https://github.com/logo.png` | ✓ |
    #   | `http://github.com/logo.png` | ✗ (not https) |
    #   | `logo.png` | ✗ (no scheme/domain) |
    #   | `ftp://example.com/logo.png` | ✗ (not https) |

    uri = base_uri.format(otp_type, label, urlencode(url_args).replace("+", "%20"))
    # final result:
    # otpauth://totp/GitHub:alice?secret=ABC123&issuer=GitHub&algorithm=SHA256&digits=8&image=https%3A%2F%2Fgithub.com%2Flogo.png

    return uri


def strings_equal(s1: str, s2: str) -> bool:

    """
    Timing-attack resistant string comparison.

    Normal comparison using == will short-circuit on the first mismatching
    character. This avoids that by scanning the whole string, though we
    still reveal to a timing attack whether the strings are the same
    length.
    """
    s1 = unicodedata.normalize("NFKC", s1)
    s2 = unicodedata.normalize("NFKC", s2)
    return compare_digest(s1.encode("utf-8"), s2.encode("utf-8"))
#   This is a security function for comparing strings without leaking timing information.
#   The Problem:
#   Normal == comparison is fast but leaks information
#   they normalize the unicode, and do a constant time compare
#   "４８２１９３" (fullwidth) → "482193" (normal)
#   "𝟒𝟖𝟐𝟏𝟗𝟑" (math symbols) → "482193" (normal)
#   compare_digest from hmac will always take same time, regardless where mismatch occurs.