#!/usr/bin/env node
/*
 * Copyright (c) 2018-2021 29k International AB
 */

// TERMINOLOGY
//
// TODO: define terminology better. this is what's current:
//
// primary   -- the primary key (with a protocol)
// chain    -- a set of "secrets" for categories
// category -- a category separates secrets into sub groups
// secret   -- a specific encryption key (encrypted with the primary key)
//             for a specific category, protocol and version
//
// PROTOCOL
//
// The protocol flow looks like this:
//
// 1. Fetch user's salt from server
// 2. Derive primary key from user password and salt
// 3. Store primary key ("remember me")
// 4. Generate "category key", encrypt with random nonce and primary key
// 5. Upload used nonce and encrypted key
//
// Used algorithm:
// 1. Deriving password: argon2id
// 2. Encryption: argon2id + XChaCha20 Poly1305 IETF
//
// Alternative algorithms:
// 1. argon2id + libsodium secretbox (XSalsa20 Poly1305 MAC)
// 2. PKDF2 + AES256-GCM
//
// KNOWN ISSUES
//
// 1. Values can be copied / moved from one "database entry" to another.
//    There is nothing in the "additional" data that binds it to a
//    specific entry, only to a specific protocol version.
const sodium = require('libsodium-wrappers');

// OPS_LIMIT is sodium.crypto_pwhash_OPSLIMIT_MODERATE
//
// The constant sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE is 2 but it
// seem OPSLIMIT_MODERATE work fine on my machine. We can decrease this
// if it's unbearable on older devices.
//
// Based on the documentation here[1], it's better to keep this
// a 3 and lower memory limit.
// [1] https://doc.libsodium.org/password_hashing/default_phf
const OPS_LIMIT = 3;

// MEM_LIMIT is sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE.
const MEM_LIMIT = 64 * 1024 * 1024;

// PROTOCOL_VERSION_1 is prepended to all ciphertext and keys will also
// have this tied to it. It dictates the algorithm used together with
// any knobs for it like operation and memory limits.
const PROTOCOL_VERSION_1 = '29k1';

const CATEGORY_PRIMARY = '0';

// CATEGORY_JOURNALING is an example cateogry. Ciphertext will contain
// the category to allow us to have different keys for different
// purposes.
const CATEGORY_JOURNALING = 'j';

// deriveKeyFromPassword derives a 256-bit key from a password and a
// 128-bit salt using argon2id.
// https://doc.libsodium.org/password_hashing/default_phf
const deriveKeyFromPassword = async (password, salt) => {
  await sodium.ready;
  const start = performance.now();
  const key = sodium.crypto_pwhash(
    32, // 256-bit key
    password,
    salt,
    OPS_LIMIT,
    MEM_LIMIT,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
  const time = ((performance.now() - start) / 1e3).toPrecision(3);
  console.log(`Generated primary key in ${time}s.`);
  return key;
};

// generateKey generates a symmetric encryption key.
const generateKey = async () => {
  await sodium.ready;
  return sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
};

// generateSalt generates a 128-bit salt
const generateSalt = async () => {
  await sodium.ready;
  return sodium.randombytes_buf(16);
};

// generateNonce generates a 192-bit nonce.
const generateNonce = async () => {
  await sodium.ready;
  return sodium.randombytes_buf(24);
};

// encrypt encrypts a message with a key and a nonce to keep it
// confidential. An authentication tag is automatically added to it.
const encrypt = async (plaintext, nonce, { protocol, key }) => {
  await sodium.ready;
  if (protocol !== PROTOCOL_VERSION_1) {
    throw new Error('Unsupported protocol');
  }
  const additional = protocol;
  return sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    additional,
    null,
    nonce,
    key,
  );
};

// decrypt decrypts a message and verifies the authentication tag to
// make sure it hasn't been tampered with.
const decrypt = async (ciphertext, nonce, { protocol, key }) => {
  await sodium.ready;
  if (protocol !== PROTOCOL_VERSION_1) {
    throw new Error('Unsupported protocol');
  }
  const additional = protocol;
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    additional,
    nonce,
    key,
  );
};

// createChainSecret generates a new encryption key and encrypts it
// using the primary key, and finally wraps it with nonce, protocol
// version, key version and the category which this key is used for.
//
// The encryption key is encrypted using the primary key. Once encrypted,
// it is referred to as "secret".
const createChainSecret = async (primary, category, version) => {
  const nonce = await generateNonce();
  const key = await generateKey();
  // TODO: do we gain anything by encrypting "chain nonce" with primary key
  return {
    protocol: PROTOCOL_VERSION_1,
    version,
    category,
    nonce,
    encryptedKey: await encrypt(key, nonce, primary),
    createdAt: new Date().toISOString(),
  };
};

// decryptChainSecret decrypts a chain secret using the primary key.
const decryptChainSecret = async (primary, chainSecret) => {
  const { encryptedKey, nonce, ...rest } = chainSecret;
  return {
    ...rest,
    key: await decrypt(encryptedKey, nonce, primary),
    nonce,
  };
};

// findChainSecret returns the latest encryption key for a specific
// category.
const findChainSecret = (chain, category, protocol, version) =>
  chain.find(
    (item) =>
      item.category === category &&
      (protocol === undefined || item.protocol === protocol) &&
      (version === undefined || item.version === version),
  );

const serializeKeyChain = (chain) =>
  chain.map(({ encryptedKey, nonce, createdAt, ...key }) => ({
    key: createCipherPrefix(key, nonce) + sodium.to_base64(encryptedKey),
    createdAt,
  }));

const serializePrimaryKey = ({ protocol, version, key }) =>
  createCipherPrefix(
    {
      protocol,
      category: CATEGORY_PRIMARY,
      version,
    },
    '', // primary key does not have a nonce
  ) + sodium.to_base64(key);

// createCipherPrefix creates a prefix suitable to prepend to a
// ciphertext to make it easier to decrypt the cipher in the future.
//
// The format is eg: $29k1$category$1$nonce.
const createCipherPrefix = ({ protocol, category, version }, nonce) =>
  ['', protocol, category, version, sodium.to_base64(nonce), ''].join('$');

const marshallEncrypted = (chainSecret, nonce, ciphertext) =>
  createCipherPrefix(chainSecret, nonce) + sodium.to_base64(ciphertext);

const unmarshallEncrypted = (value) => {
  const [
    preamble,
    protocol,
    category,
    version,
    nonce,
    ciphertext,
  ] = value.split('$', 6);
  if (preamble !== '' || protocol !== PROTOCOL_VERSION_1) {
    throw new Error('Unsupported protocol');
  }
  return {
    protocol,
    category,
    version: Number.parseInt(version),
    nonce: sodium.from_base64(nonce),
    ciphertext: sodium.from_base64(ciphertext),
  };
};

// step1 is an example of how to encrypt things
const step1 = async (plaintext, primary, chain, category) => {
  const secret = findChainSecret(chain, CATEGORY_JOURNALING);

  const nonce = await generateNonce();
  const encrypted = await encrypt(
    plaintext,
    nonce,
    await decryptChainSecret(primary, secret),
  );
  return marshallEncrypted(secret, nonce, encrypted);
};

// step2 is an example of how to decrypt things
const step2 = async (marshalled, primary, chain) => {
  const {
    protocol,
    category,
    version,
    nonce,
    ciphertext,
  } = unmarshallEncrypted(marshalled);

  const secret = findChainSecret(chain, category, protocol, version);
  if (!secret) {
    throw new Error('Unknown encryption key');
  }

  const bytes = await decrypt(
    ciphertext,
    nonce,
    await decryptChainSecret(primary, secret),
  );
  return sodium.to_string(bytes);
};

async function main() {
  const args = process.argv.splice(2);
  const plaintext = 'hello crypto';
  const password = 'qwerty';

  // salt: stored with the user / key
  await sodium.ready;
  const salt = args[0] ? sodium.from_base64(args[0]) : await generateSalt();

  // primary key derived from password. Never leaves the user's device
  // and will be stored as secure as possible:
  // - iOS uses key chain sharing
  // - Android Keystore (where available)
  // TODO: use salt to obfuscate primary key stored in local storage?
  const primary = {
    protocol: PROTOCOL_VERSION_1,
    version: 1,
    category: CATEGORY_PRIMARY,
    key: await deriveKeyFromPassword(password, salt),
  };

  console.log('*** local device');
  console.log('data', {
    primary: serializePrimaryKey(primary),
  });

  // chain contains all content encryption secrets.
  //
  // This will be stored on a "user" object.
  //
  // (We do not store anything relating to password here. Firebase Auth
  // handles that for us.)
  //
  // This need to be sorted on version and / or creation date.
  const chain = [await createChainSecret(primary, CATEGORY_JOURNALING, 1)];

  const encrypted = await step1(plaintext, primary, chain, CATEGORY_JOURNALING);
  const decrypted = await step2(encrypted, primary, chain);

  // this is the data that will be stored in the database
  console.log('*** remote database');
  // user database
  console.log('user', {
    primary: { protocol: PROTOCOL_VERSION_1, salt: sodium.to_base64(salt) },
    chain: serializeKeyChain(chain),
  });
  // example "entries" collection, can really be anything
  console.log('entries', {
    value: encrypted,
  });

  console.log('*** encryption');
  console.log('encrypted', encrypted);
  console.log('decrypted', decrypted);
}

main();
