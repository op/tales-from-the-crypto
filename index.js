#!/usr/bin/env node
/*
 * Copyright (c) 2018-2021 29k International AB
 */

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

// generateScheme generates a new scheme.
//
// A scheme contains a newly generated nonce, newly generated encryption key
// together with protocol version, key version and category.
//
// The encryption key is encrypted using the primary key.
const generateScheme = async (primary, category, version) => {
  const nonce = await generateNonce();
  const key = await generateKey();
  // TODO: do we gain anything by encrypting nonce with primary key
  return {
    protocol: PROTOCOL_VERSION_1,
    version,
    category,
    nonce,
    encryptedKey: await encrypt(key, nonce, primary),
    createdAt: new Date().toISOString(),
  };
};

// decryptScheme decrypts a scheme using the primary key.
const decryptScheme = async (primary, scheme) => {
  const { encryptedKey, nonce, ...rest } = scheme;
  return {
    ...rest,
    key: await decrypt(encryptedKey, nonce, primary),
    nonce,
  };
};

// findScheme returns the latest encryption key for a specific category and
// optionally a specific protocol version and/or key version.
const findScheme = (schemes, category, protocol, version) =>
  schemes.find(
    (scheme) =>
      scheme.category === category &&
      (protocol === undefined || scheme.protocol === protocol) &&
      (version === undefined || scheme.version === version),
  );

const serializeSchemes = (schemes) =>
  schemes.map(serializeScheme);

const serializeScheme = ({ encryptedKey, nonce, createdAt, ...key }) => ({
    key: createCipherPrefix(key, nonce) + sodium.to_base64(encryptedKey),
    createdAt,
  });

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

const marshallEncrypted = (scheme, nonce, ciphertext) =>
  createCipherPrefix(scheme, nonce) + sodium.to_base64(ciphertext);

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
const step1 = async (plaintext, primary, schemes, category) => {
  const scheme = findScheme(schemes, CATEGORY_JOURNALING);
  if (!scheme) {
    throw new Error('Unknown encryption scheme');
  }

  const nonce = await generateNonce();
  const encrypted = await encrypt(
    plaintext,
    nonce,
    await decryptScheme(primary, scheme),
  );
  return marshallEncrypted(scheme, nonce, encrypted);
};

// step2 is an example of how to decrypt things
const step2 = async (marshalled, primary, schemes) => {
  const {
    protocol,
    category,
    version,
    nonce,
    ciphertext,
  } = unmarshallEncrypted(marshalled);

  const scheme = findScheme(schemes, category, protocol, version);
  if (!scheme) {
    throw new Error('Unknown encryption scheme');
  }

  const bytes = await decrypt(
    ciphertext,
    nonce,
    await decryptScheme(primary, scheme),
  );
  return sodium.to_string(bytes);
};

async function main() {
  const args = process.argv.splice(2);
  const plaintext = 'Shave and a haircut, two bits!';
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
    category: CATEGORY_PRIMARY,
    version: 1,
    key: await deriveKeyFromPassword(password, salt),
  };

  console.log('*** local device');
  console.log('data', {
    primary: serializePrimaryKey(primary),
  });

  // schemes contains all encryption schemes.
  //
  // This will be stored on a "user" object.
  //
  // (We do not store anything relating to password here. Firebase Auth
  // handles that for us.)
  //
  // This need to be sorted on version and / or creation date.
  const schemes = [await generateScheme(primary, CATEGORY_JOURNALING, 1)];

  const encrypted = await step1(plaintext, primary, schemes, CATEGORY_JOURNALING);
  const decrypted = await step2(encrypted, primary, schemes);

  // this is the data that will be stored in the database
  console.log('*** remote database');
  // user database
  console.log('user', {
    primary: { protocol: PROTOCOL_VERSION_1, salt: sodium.to_base64(salt) },
    schemes: serializeSchemes(schemes),
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
