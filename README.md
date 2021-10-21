# Encryption protocol

Proof of concept; encryption based on user password.

## TERMINOLOGY

> TODO: improve terminology

 * primary   -- the primary key (with a protocol)
 * schemes   -- a set of schemes for different categories
 * scheme    -- a specific encryption key (encrypted with the primary key)
                for a specific category, protocol and version
 * category  -- a category separates different schemes into groups (eg journaling)

## PROTOCOL

The protocol flow looks like this:

1. Fetch user's salt from server
2. Derive primary key from user password and salt
3. Store primary key on local device (for "remember me")
4. Generate scheme for category (encrypt with random nonce and primary key)
5. Upload used nonce and encrypted key

If user changes password:

1. Derive new primary key
2. Re-encrypt all keys for all schemes
3. Generate new scheme version with new key for all categories
4. Upload new schemes

## Algorithms

1. Key derivation: argon2id
2. Encryption: XChaCha20 Poly1305 IETF

Alternative algorithms:
1. argon2id + libsodium secretbox (XSalsa20 Poly1305 MAC)
2. PKDF2 + AES256-GCM

## KNOWN ISSUES

* Values can be copied / moved from one "database entry" to another.
   There is nothing in the "additional" data that binds it to a
   specific entry, only to a specific protocol version.

* The only real category right now is journaling. Is it overkill to think about
  it?

* If password is changed because previous password was stolen, current
  encryption keys might be at risk.

* Encrypted keys are stored on server. Alternative would be to not store keys
  at all. This would force us to re-encrypt all data on password change.

## Example

```
$ ./index.js 6v78rQHoefeqOPTubwFNNA
Generated primary key in 0.780s.
*** local device
data { primary: '$29k1$0$1$$-hQbC3g54I-HkqjmlxKdYmWuMwM3l0AkMf1yNYwZ1pc' }
*** remote database
user {
  primary: { protocol: '29k1', salt: '6v78rQHoefeqOPTubwFNNA' },
  schemes: [
    {
      key: '$29k1$j$1$eWDp4bT3uvGp8eW_fNLq4GaoEzw_axKB$jExMAJLnqMe5L10qsN4AsAg4P4hQQsH1Z2e7ZVwApxef76ra57GWGHDbEynMn4TF',
      createdAt: '2021-10-20T20:57:58.878Z'
    }
  ]
}
entries {
  value: '$29k1$j$1$-3QCtjQGLm4f1fN9WoP7i8ij0_b3XlF4$pCEmwl6PSTcJvEjjvFL9J6ODUuuYkgw-w90eYxzUGxFMHCw7GK5f9Mku2KvJ5A'
}
*** encryption
encrypted $29k1$j$1$-3QCtjQGLm4f1fN9WoP7i8ij0_b3XlF4$pCEmwl6PSTcJvEjjvFL9J6ODUuuYkgw-w90eYxzUGxFMHCw7GK5f9Mku2KvJ5A
decrypted Shave and a haircut, two bits!
```
