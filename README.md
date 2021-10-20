# Encryption protocol

Proof of concept; encryption based on user password.

## TERMINOLOGY

> TODO: improve terminology

> TODO: do not use "master". Primary?

 * primary   -- the primary key (with a protocol)
 * chain    -- a set of "secrets" for categories
 * category -- a category separates secrets into sub groups
 * secret   -- a specific encryption key (encrypted with the master key)
               for a specific category, protocol and version
## PROTOCOL

The protocol flow looks like this:

1. Fetch user's salt from server
2. Derive master key from user password and salt
3. Store master key ("remember me")
4. Generate "category key", encrypt with random nonce and master key
5. Upload used nonce and encrypted key

Used algorithm:
1. Key derivation: argon2id
2. Encryption: XChaCha20 Poly1305 IETF

Alternative algorithms:
1. argon2id + libsodium secretbox (XSalsa20 Poly1305 MAC)
2. PKDF2 + AES256-GCM

## KNOWN ISSUES

* Values can be copied / moved from one "database entry" to another.
   There is nothing in the "additional" data that binds it to a
   specific entry, only to a specific protocol version.
