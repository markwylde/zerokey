// Base64url encoding/decoding utilities

/**
 * Encodes an ArrayBuffer to a base64url string.
 * 
 * Base64url is a URL-safe variant of base64 encoding that replaces
 * '+' with '-', '/' with '_', and removes padding '=' characters.
 * This makes it suitable for use in URLs and filenames.
 * 
 * @param {ArrayBuffer} buffer - The binary data to encode.
 * @returns {string} The base64url-encoded string.
 * @internal
 */
function base64urlEncode(buffer: ArrayBuffer): string {
  const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Decodes a base64url string to an ArrayBuffer.
 * 
 * Reverses the base64url encoding by restoring the standard base64
 * characters and padding before decoding to binary data.
 * 
 * @param {string} str - The base64url-encoded string to decode.
 * @returns {ArrayBuffer} The decoded binary data.
 * @internal
 */
function base64urlDecode(str: string): ArrayBuffer {
  const base64 = str
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(str.length + ((4 - (str.length % 4)) % 4), '=');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Type definitions

/**
 * Represents an asymmetric cryptographic key pair for ECDH operations.
 * 
 * @interface KeyPair
 * @property {string} publicKey - The public key encoded as a base64url string.
 *                                This key can be safely shared with others.
 * @property {CryptoKey} privateKey - The private key as a native CryptoKey object.
 *                                    This key must be kept secret and never shared.
 * 
 * @example
 * ```typescript
 * const keyPair = await generateKeyPair();
 * console.log(keyPair.publicKey); // Safe to share
 * // keyPair.privateKey is kept secret
 * ```
 */
export interface KeyPair {
  publicKey: string;
  privateKey: CryptoKey;
}

/**
 * Internal structure for storing encrypted data along with the ephemeral public key.
 * Used in hybrid encryption scheme.
 * 
 * @interface EncryptedPayload
 * @internal
 */
interface EncryptedPayload {
  ephemeralPublicKey: string;
  encryptedData: string;
}

/**
 * Generates a new ECDH (Elliptic Curve Diffie-Hellman) key pair using the P-256 curve.
 * 
 * This function creates a cryptographically secure key pair suitable for key exchange
 * and hybrid encryption operations. The P-256 curve (also known as secp256r1) provides
 * 128-bit security strength.
 * 
 * @returns {Promise<KeyPair>} A promise that resolves to a KeyPair object containing
 *                             the public key (as base64url string) and private key (as CryptoKey).
 * 
 * @throws {Error} Throws if the Web Crypto API is not available or key generation fails.
 * 
 * @example
 * ```typescript
 * const keyPair = await generateKeyPair();
 * // Store keyPair.publicKey in database or share with others
 * // Keep keyPair.privateKey secure and never transmit it
 * ```
 * 
 * @see {@link https://www.w3.org/TR/WebCryptoAPI/#ecdh|W3C Web Crypto API ECDH}
 */
export async function generateKeyPair(): Promise<KeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256'
    },
    true,
    ['deriveKey']
  );

  const publicKeyExported = await exportPublicKey(keyPair.publicKey);

  return {
    publicKey: publicKeyExported,
    privateKey: keyPair.privateKey
  };
}

/**
 * Exports a CryptoKey public key to a base64url-encoded string format.
 * 
 * This function converts a native CryptoKey object to a portable string format
 * that can be safely transmitted over networks, stored in databases, or shared
 * between different systems. The base64url encoding is URL-safe and doesn't
 * require additional encoding.
 * 
 * @param {CryptoKey} publicKey - The public key to export. Must be an ECDH P-256 public key.
 * 
 * @returns {Promise<string>} A promise that resolves to the base64url-encoded public key.
 * 
 * @throws {Error} Throws if the key export fails or if the provided key is not a valid public key.
 * 
 * @example
 * ```typescript
 * const keyPair = await generateKeyPair();
 * const publicKeyString = await exportPublicKey(keyPair.publicKey);
 * // publicKeyString can now be stored or transmitted
 * ```
 */
export async function exportPublicKey(publicKey: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey('raw', publicKey);
  return base64urlEncode(exported);
}

/**
 * Imports a public key from a base64url-encoded string to a CryptoKey object.
 * 
 * This function converts a portable string representation of a public key back
 * into a native CryptoKey object that can be used for cryptographic operations.
 * The key must be a valid ECDH P-256 public key in raw format.
 * 
 * @param {string} publicKeyString - The base64url-encoded public key string to import.
 * 
 * @returns {Promise<CryptoKey>} A promise that resolves to the imported public key as a CryptoKey object.
 * 
 * @throws {Error} Throws if the string is not a valid base64url-encoded key or if import fails.
 * 
 * @example
 * ```typescript
 * const publicKeyString = "your-base64url-encoded-public-key";
 * const publicKey = await importPublicKey(publicKeyString);
 * // publicKey can now be used for encryption operations
 * ```
 */
export async function importPublicKey(publicKeyString: string): Promise<CryptoKey> {
  const keyData = base64urlDecode(publicKeyString);
  return await crypto.subtle.importKey(
    'raw',
    keyData,
    {
      name: 'ECDH',
      namedCurve: 'P-256'
    },
    false,
    []
  );
}

/**
 * Serializes a private key to a JSON string for secure storage.
 * 
 * This function exports a private key in JWK (JSON Web Key) format, which preserves
 * all key parameters and can be safely stored in secure storage systems. The resulting
 * string contains sensitive key material and must be protected accordingly.
 * 
 * @param {CryptoKey} privateKey - The private key to serialize. Must be an ECDH P-256 private key.
 * 
 * @returns {Promise<string>} A promise that resolves to the JSON-serialized private key.
 * 
 * @throws {Error} Throws if the key export fails or if the provided key is not extractable.
 * 
 * @example
 * ```typescript
 * const keyPair = await generateKeyPair();
 * const serialized = await serializePrivateKey(keyPair.privateKey);
 * // Store 'serialized' in secure storage (e.g., encrypted database, secure keychain)
 * ```
 * 
 * @security This function returns sensitive key material. Ensure the output is stored
 *           securely and never transmitted over insecure channels.
 */
export async function serializePrivateKey(privateKey: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey('jwk', privateKey);
  return JSON.stringify(exported);
}

/**
 * Deserializes a private key from a JSON string back to a CryptoKey object.
 * 
 * This function imports a private key that was previously serialized using
 * serializePrivateKey(). It restores the key to a usable CryptoKey object
 * for cryptographic operations.
 * 
 * @param {string} privateKeyString - The JSON-serialized private key string to deserialize.
 * 
 * @returns {Promise<CryptoKey>} A promise that resolves to the imported private key as a CryptoKey object.
 * 
 * @throws {Error} Throws if the string is not valid JSON or contains an invalid JWK structure.
 * 
 * @example
 * ```typescript
 * // Retrieve serialized key from secure storage
 * const serialized = await getFromSecureStorage('privateKey');
 * const privateKey = await deserializePrivateKey(serialized);
 * // privateKey can now be used for decryption operations
 * ```
 * 
 * @security Handle the input string with care as it contains sensitive key material.
 */
export async function deserializePrivateKey(privateKeyString: string): Promise<CryptoKey> {
  const jwk = JSON.parse(privateKeyString);
  return await crypto.subtle.importKey(
    'jwk',
    jwk,
    {
      name: 'ECDH',
      namedCurve: 'P-256'
    },
    true,
    ['deriveKey']
  );
}

/**
 * Derives a shared secret key using ECDH key agreement.
 * 
 * This function performs the ECDH key agreement protocol to derive
 * a shared AES-256 key from a private key and a public key. The
 * resulting key can be used for symmetric encryption/decryption.
 * 
 * @param {CryptoKey} privateKey - The private key for the ECDH operation.
 * @param {CryptoKey} publicKey - The public key for the ECDH operation.
 * @returns {Promise<CryptoKey>} A promise that resolves to the derived AES-256 key.
 * @internal
 */
async function deriveSharedSecret(privateKey: CryptoKey, publicKey: CryptoKey): Promise<CryptoKey> {
  return await crypto.subtle.deriveKey(
    {
      name: 'ECDH',
      public: publicKey
    },
    privateKey,
    {
      name: 'AES-GCM',
      length: 256
    },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypts a string using AES-GCM with a random IV.
 * 
 * AES-GCM provides authenticated encryption, ensuring both confidentiality
 * and integrity of the data. A 96-bit random IV is generated for each
 * encryption operation and prepended to the encrypted data.
 * 
 * @param {CryptoKey} key - The AES-256 key for encryption.
 * @param {string} data - The plaintext string to encrypt.
 * @returns {Promise<ArrayBuffer>} A promise that resolves to the combined IV + encrypted data.
 * @internal
 */
async function aesEncrypt(key: CryptoKey, data: string): Promise<ArrayBuffer> {
  const encoder = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    key,
    encoder.encode(data)
  );

  // Combine iv and encrypted data
  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encrypted), iv.length);

  return combined.buffer;
}

/**
 * Decrypts data that was encrypted using AES-GCM.
 * 
 * Extracts the IV from the beginning of the combined data and uses it
 * along with the provided key to decrypt the remaining encrypted data.
 * AES-GCM also verifies the authenticity of the data during decryption.
 * 
 * @param {CryptoKey} key - The AES-256 key for decryption.
 * @param {ArrayBuffer} combinedData - The combined IV + encrypted data.
 * @returns {Promise<string>} A promise that resolves to the decrypted plaintext string.
 * @throws {Error} Throws if decryption fails or authentication tag verification fails.
 * @internal
 */
async function aesDecrypt(key: CryptoKey, combinedData: ArrayBuffer): Promise<string> {
  const data = new Uint8Array(combinedData);
  const iv = data.slice(0, 12);
  const encrypted = data.slice(12);

  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    key,
    encrypted
  );

  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}

/**
 * Encrypts a secret using hybrid encryption (ECDH + AES-GCM).
 * 
 * This function implements a hybrid encryption scheme that combines the security of
 * asymmetric encryption with the efficiency of symmetric encryption. It generates
 * an ephemeral key pair, derives a shared secret using ECDH, and then encrypts
 * the data using AES-GCM with the derived key.
 * 
 * The encryption process:
 * 1. Generates an ephemeral ECDH key pair
 * 2. Derives a shared AES key using ECDH with the recipient's public key
 * 3. Encrypts the secret using AES-GCM
 * 4. Packages the ephemeral public key with the encrypted data
 * 
 * @param {string} secret - The secret data to encrypt. Can be any string value.
 * @param {string} publicKeyString - The recipient's public key as a base64url-encoded string.
 * 
 * @returns {Promise<string>} A promise that resolves to a base64url-encoded encrypted payload
 *                           containing both the ephemeral public key and encrypted data.
 * 
 * @throws {Error} Throws if encryption fails or if the public key is invalid.
 * 
 * @example
 * ```typescript
 * const recipientPublicKey = "their-public-key-string";
 * const secretMessage = "This is a secret message";
 * 
 * const encrypted = await encryptWithPublicKey(secretMessage, recipientPublicKey);
 * // 'encrypted' can be safely transmitted to the recipient
 * // Only the holder of the corresponding private key can decrypt it
 * ```
 * 
 * @see {@link decryptWithPrivateKey} for the corresponding decryption function
 */
export async function encryptWithPublicKey(
  secret: string,
  publicKeyString: string
): Promise<string> {
  // Generate ephemeral keypair for this encryption
  const ephemeralKeyPair = await generateKeyPair();

  // Import recipient's public key
  const recipientPublicKey = await importPublicKey(publicKeyString);

  // Derive shared secret
  const sharedKey = await deriveSharedSecret(ephemeralKeyPair.privateKey, recipientPublicKey);

  // Encrypt the secret with AES-GCM
  const encryptedData = await aesEncrypt(sharedKey, secret);

  // Create the final payload: ephemeral public key + encrypted data
  const payload: EncryptedPayload = {
    ephemeralPublicKey: ephemeralKeyPair.publicKey,
    encryptedData: base64urlEncode(encryptedData)
  };

  return base64urlEncode(new TextEncoder().encode(JSON.stringify(payload)));
}

/**
 * Decrypts data that was encrypted using hybrid encryption (ECDH + AES-GCM).
 * 
 * This function reverses the encryption performed by encryptWithPublicKey().
 * It extracts the ephemeral public key from the encrypted payload, derives
 * the same shared secret using ECDH, and then decrypts the data using AES-GCM.
 * 
 * The decryption process:
 * 1. Extracts the ephemeral public key from the encrypted payload
 * 2. Derives the shared AES key using ECDH with the private key
 * 3. Decrypts the data using AES-GCM with the derived key
 * 
 * @param {string} encryptedString - The base64url-encoded encrypted payload containing
 *                                   the ephemeral public key and encrypted data.
 * @param {CryptoKey} privateKey - The recipient's private key for decryption.
 * 
 * @returns {Promise<string>} A promise that resolves to the decrypted secret string.
 * 
 * @throws {Error} Throws "Failed to decrypt secret" if decryption fails for any reason,
 *                 including invalid encrypted data, wrong private key, or corrupted payload.
 * 
 * @example
 * ```typescript
 * const keyPair = await generateKeyPair();
 * // Receive encrypted message from sender
 * const encryptedMessage = "encrypted-payload-from-sender";
 * 
 * try {
 *   const decrypted = await decryptWithPrivateKey(encryptedMessage, keyPair.privateKey);
 *   console.log("Decrypted message:", decrypted);
 * } catch (error) {
 *   console.error("Decryption failed:", error);
 * }
 * ```
 * 
 * @see {@link encryptWithPublicKey} for the corresponding encryption function
 */
export async function decryptWithPrivateKey(
  encryptedString: string,
  privateKey: CryptoKey
): Promise<string> {
  try {
    // Decode the payload
    const payloadBytes = base64urlDecode(encryptedString);
    const payloadText = new TextDecoder().decode(payloadBytes);
    const payload: EncryptedPayload = JSON.parse(payloadText);

    // Import ephemeral public key
    const ephemeralPublicKey = await importPublicKey(payload.ephemeralPublicKey);

    // Derive shared secret
    const sharedKey = await deriveSharedSecret(privateKey, ephemeralPublicKey);

    // Decrypt the data
    const encryptedData = base64urlDecode(payload.encryptedData);
    return await aesDecrypt(sharedKey, encryptedData);
  } catch (error) {
    console.error('Decryption failed:', error);
    throw new Error('Failed to decrypt secret');
  }
}
