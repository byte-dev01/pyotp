# In your Python shell:
import pyotp

# Generate a secret
secret = pyotp.random_base32()
print(f"Secret: {secret}")

# Create a TOTP and get current code
totp = pyotp.TOTP(secret)
print(f"Current code: {totp.now()}")

# Verify it
code = totp.now()
print(f"Valid? {totp.verify(code)}")
#        OTP (base class)
#        ┌─────────────────────────┐
#        │ secret                  │
#        │ digits                  │
#        │ digest                  │
#        │ generate_otp()          │
#        │ byte_secret()           │
#        │ int_to_bytestring()     │
#        └───────────┬─────────────┘
#                    │ inherits
#        ┌───────────┴─────────────┐
#        │                         │
#        ▼                         ▼
#┌───────────────┐         ┌───────────────┐
#│ TOTP          │         │ HOTP          │
#├───────────────┤         ├───────────────┤
#│ + interval    │         │ + initial_count│
#│ + now()       │         │ + at(count)   │
#│ + timecode()  │         │ + verify()    │
#└───────────────┘         └───────────────┘
#
#   totp = pyotp.TOTP("JBSWY3DPEHPK3PXP")
#   TOTP.__init__() runs:
#    │
#    ├── self.interval = 30
#    │
#    └── super().__init__(...) calls OTP.__init__()
#            │
#            ├── self.secret = "JBSWY3DPEHPK3PXP"
#            ├── self.digits = 6
#            └── self.digest = hashlib.sha1
"Then TOTP has everything from both classes"
#   totp.interval  # 30         ← from TOTP
#   totp.secret    # "JBSWY..."  ← from OTP
#   totp.digits    # 6           ← from OTP
#       code = totp.now()
"""
totp.now()                              TOTP method
    │
    └── self.generate_otp(self.timecode(now))
            │                    │
            │                    └── TOTP method
            │                        Returns: 56843861 (time / 30)
            │
            └── OTP method (inherited!)
                Does the HMAC magic
                Returns: "482193"
"""
# TOTP.now() calls self.generate_otp(), but TOTP doesn't define 
# generate_otp().
"""

┌─────────────────────────────────────────────────────────────────┐
│ YOUR CODE                                                       │
│                                                                 │
│   totp = pyotp.TOTP("SECRET")                                   │
│   code = totp.now()                                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ TOTP (totp.py)                                                  │
│                                                                 │
│   def now(self):                                                │
│       counter = self.timecode(datetime.now())  # TOTP method    │
│       return self.generate_otp(counter)  ──────────┐            │
│                                                    │            │
└────────────────────────────────────────────────────│────────────┘
                                                     │
                              ┌──────────────────────┘
                              │ calls inherited method
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ OTP (otp.py)                                                    │
│                                                                 │
│   def generate_otp(self, input):                                │
│       # HMAC-SHA1                                               │
│       # Truncation                                              │
│       # Return 6 digits                                         │
│       return "482193"                                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
"""
"""
totp.verify("482193")
    │
    ├── Get current time
    │
    ├── Generate what the code SHOULD be:
    │       self.at(for_time)
    │           │
    │           └── self.generate_otp(self.timecode(for_time))
    │                       │                │
    │                       │                └── TOTP: time → counter
    │                       │
    │                       └── OTP: counter → "482193"
    │
    └── Compare user input vs expected:
            utils.strings_equal("482193", "482193")
                │
                └── True! Valid code.

"""
# Next, how does generated_otp work?
# generate_otp calls byte_secret() and int_to_bytestring()
#
#   HMAC requires two byte inputs:
"""

hmac.new(key, message, hash_function)
         │      │
         │      └── Must be bytes
         └── Must be bytes
```

But we have:
- Secret: `"JBSWY3DPEHPK3PXP"` (string)
- Counter: `56843861` (integer)
"""
"""
┌─────────────────────────────────────────────────────────────┐
│ generate_otp(56843861)                                      │
│                                                             │
│   self.byte_secret()                                        │
│       "JBSWY3DPEHPK3PXP" → b'Hello!\xde\xad...'             │
│                                                             │
│   self.int_to_bytestring(56843861)                          │
│       56843861 → b'\x00\x00\x00\x00\x03dz\xd5'              │
│                                                             │
│   hmac.new(                                                 │
│       b'Hello!\xde\xad...',      ← secret as bytes          │
│       b'\x00\x00\x00\x00\x03dz\xd5',  ← counter as bytes    │
│       hashlib.sha1                                          │
│   )                                                         │
└─────────────────────────────────────────────────────────────┘



"""

#   totp.now()
#        generate_otp(56843861)
#               byte_secret()         → Secret as bytes
#               int_to_bytestring()   → Counter as bytes
#               hmac.new(secret_bytes, counter_bytes, sha1)
#                   20-byte hash → truncate → "482193"
#
