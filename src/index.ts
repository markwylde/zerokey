/**
 * @module zerokey
 *
 * Zero-knowledge cross-domain secret sharing library using ECDH encryption.
 *
 * This library provides a secure method for transferring secrets (like API keys, tokens, or other
 * sensitive data) between different domains without the authentication domain ever having access
 * to the client's private key or the client domain having direct access to the plaintext secret.
 *
 * ## Key Features
 *
 * - **Zero-Knowledge Protocol**: The auth domain never sees the client's private key
 * - **Cross-Domain Support**: Securely transfer secrets between different origins
 * - **Modern Crypto**: Uses ECDH (Elliptic Curve Diffie-Hellman) with P-256 curve and AES-GCM
 * - **Browser Native**: Built on the Web Crypto API, no external dependencies
 * - **TypeScript Support**: Fully typed for enhanced developer experience
 *
 * ## How It Works
 *
 * 1. **Client generates a key pair**: An ephemeral ECDH key pair is created
 * 2. **Public key sent to auth domain**: Only the public key is shared
 * 3. **Auth domain encrypts secret**: The secret is encrypted using hybrid encryption
 * 4. **Encrypted secret returned**: Via URL fragment (never hits the server)
 * 5. **Client decrypts**: Using the private key that never left the client
 *
 * ## Usage Example
 *
 * ### Client-side (receiving secrets)
 * ```typescript
 * import { initSecretClient, getSecret } from 'zerokey';
 *
 * // Initialize the client with your auth domain
 * await initSecretClient('https://auth.example.com/zerokey');
 *
 * // Listen for when the secret is ready
 * window.addEventListener('zerokey:ready', () => {
 *   const secret = getSecret();
 *   // Use the secret for API calls
 * });
 * ```
 *
 * ### Server-side (sharing secrets)
 * ```typescript
 * import { initSecretServer, setSecret } from 'zerokey/server';
 *
 * // Initialize the server handler
 * initSecretServer();
 *
 * // After authenticating the user, provide their secret
 * const userApiKey = await getUserApiKey(userId);
 * setSecret(userApiKey);
 * ```
 *
 * ### Direct encryption (advanced usage)
 * ```typescript
 * import { generateKeyPair, encryptWithPublicKey, decryptWithPrivateKey } from 'zerokey';
 *
 * // Generate a key pair
 * const keyPair = await generateKeyPair();
 *
 * // Encrypt a message
 * const encrypted = await encryptWithPublicKey('secret message', keyPair.publicKey);
 *
 * // Decrypt the message
 * const decrypted = await decryptWithPrivateKey(encrypted, keyPair.privateKey);
 * ```
 *
 * ## Security Considerations
 *
 * - Private keys are stored in localStorage (client-side only)
 * - Secrets are passed via URL fragments (never sent to servers)
 * - Uses CSRF protection via state parameters
 * - Implements key expiration (5 minutes for pending keys)
 * - All cryptographic operations use the Web Crypto API
 *
 * @packageDocumentation
 */

// Client-side functions for receiving secrets
/**
 * Client-side secret management functions.
 *
 * These functions handle the client side of the zero-knowledge secret sharing protocol,
 * including key generation, auth flow initialization, and secret retrieval.
 *
 * @see {@link initSecretClient} - Initialize the secret sharing client
 * @see {@link getSecret} - Retrieve the decrypted secret
 * @see {@link clearSecret} - Clear stored secrets
 */
export { initSecretClient, getSecret, clearSecret } from './client.js';

// Server-side functions for sharing secrets
/**
 * Server-side secret sharing functions.
 *
 * These functions handle the server side of the zero-knowledge protocol,
 * managing the encryption and transfer of secrets to requesting clients.
 *
 * @see {@link initSecretServer} - Initialize the secret server handler
 * @see {@link setSecret} - Set the secret to be encrypted and shared
 */
export { initSecretServer, setSecret } from './server.js';

// Cryptographic utility functions
/**
 * Low-level cryptographic functions for advanced usage.
 *
 * These functions provide direct access to the underlying cryptographic operations
 * used by the zero-knowledge protocol. They can be used independently for custom
 * encryption/decryption workflows.
 *
 * @see {@link generateKeyPair} - Generate an ECDH key pair
 * @see {@link encryptWithPublicKey} - Encrypt data using hybrid encryption
 * @see {@link decryptWithPrivateKey} - Decrypt data using hybrid encryption
 * @see {@link exportPublicKey} - Export a public key to base64url format
 * @see {@link importPublicKey} - Import a public key from base64url format
 * @see {@link serializePrivateKey} - Serialize a private key for storage
 * @see {@link deserializePrivateKey} - Deserialize a stored private key
 */
export {
  generateKeyPair,
  encryptWithPublicKey,
  decryptWithPrivateKey,
  exportPublicKey,
  importPublicKey,
  serializePrivateKey,
  deserializePrivateKey
} from './crypto.js';

// Type definitions
/**
 * Core type definitions used throughout the library.
 *
 * @see {@link KeyPair} - Represents an ECDH key pair with public and private keys
 */
export type { KeyPair } from './crypto.js';
