/**
 * @module client
 *
 * Zero-knowledge secret sharing client implementation.
 *
 * This module provides client-side functionality for securely transferring secrets
 * from an authentication domain to a client application without the auth domain
 * ever having access to the client's private key.
 *
 * The zero-knowledge protocol works as follows:
 * 1. Client generates an ephemeral key pair
 * 2. Client sends only the public key to the auth domain
 * 3. Auth domain encrypts the secret with the public key
 * 4. Client receives and decrypts the secret with its private key
 * 5. The private key never leaves the client
 *
 * @packageDocumentation
 */

import {
  decryptWithPrivateKey,
  deserializePrivateKey,
  generateKeyPair,
  serializePrivateKey
} from './crypto.js';

/** localStorage key for storing the decrypted secret */
const STORAGE_KEY_SECRET = 'zerokey_secret';

/** localStorage key for storing pending authentication data */
const STORAGE_KEY_PENDING = 'zerokey_pending';

/** Expiration time for pending keys (5 minutes in milliseconds) */
const PENDING_KEY_EXPIRY = 5 * 60 * 1000;

// Type definitions
/**
 * Parameters extracted from the URL fragment after returning from the auth domain.
 * @internal
 */
interface FragmentParams {
  /** The encrypted secret received from the auth domain */
  secret: string | null;
  /** The state parameter for CSRF protection verification */
  state: string | null;
}

/**
 * Data structure for storing pending key information during the authentication flow.
 * @internal
 */
interface PendingKeyData {
  /** The serialized private key awaiting the encrypted secret */
  privateKey: string;
  /** The state parameter for CSRF protection */
  state: string;
  /** Timestamp when the pending key was created (for expiration) */
  timestamp: number;
}

// Global window extension for zerokey event
/**
 * Extends the window event map to include the zerokey:ready event.
 * This event is dispatched when the secret has been successfully decrypted and stored.
 */
declare global {
  interface WindowEventMap {
    /** Event fired when the secret is successfully decrypted and ready for use */
    'zerokey:ready': Event;
  }
}

/**
 * Checks if the current page load is a return from the authentication domain.
 * @internal
 * @returns True if the URL contains a secret parameter in the fragment
 */
function isReturningFromAuth(): boolean {
  return window.location.hash?.includes('secret=');
}

/**
 * Parses the URL fragment to extract authentication parameters.
 * @internal
 * @returns An object containing the encrypted secret and state parameters
 */
function parseFragment(): FragmentParams {
  const fragment = window.location.hash.substring(1);
  const params = new URLSearchParams(fragment);
  return {
    secret: params.get('secret'),
    state: params.get('state')
  };
}

/**
 * Removes the fragment from the URL to prevent the sensitive data from being
 * visible in the browser's address bar or history.
 * @internal
 */
function clearFragment(): void {
  window.history.replaceState(null, '', window.location.pathname + window.location.search);
}

/**
 * Stores the private key and state in localStorage while waiting for the auth flow to complete.
 * The data includes a timestamp for automatic expiration after 5 minutes.
 * @internal
 * @param privateKey - The serialized private key to store
 * @param state - The CSRF protection state parameter
 */
function storePendingKey(privateKey: string, state: string): void {
  const data: PendingKeyData = {
    privateKey,
    state,
    timestamp: Date.now()
  };
  localStorage.setItem(STORAGE_KEY_PENDING, JSON.stringify(data));
}

/**
 * Retrieves the pending key data from localStorage if it hasn't expired.
 * Automatically cleans up expired data.
 * @internal
 * @returns The pending key data if valid and not expired, null otherwise
 */
function getPendingKey(): PendingKeyData | null {
  const data = localStorage.getItem(STORAGE_KEY_PENDING);
  if (!data) return null;

  try {
    const parsed: PendingKeyData = JSON.parse(data);
    const age = Date.now() - parsed.timestamp;

    if (age > PENDING_KEY_EXPIRY) {
      localStorage.removeItem(STORAGE_KEY_PENDING);
      return null;
    }

    return parsed;
  } catch (error) {
    localStorage.removeItem(STORAGE_KEY_PENDING);
    return null;
  }
}

/**
 * Removes the pending key data from localStorage.
 * @internal
 */
function clearPendingKey(): void {
  localStorage.removeItem(STORAGE_KEY_PENDING);
}

/**
 * Initializes the zero-knowledge secret sharing client.
 *
 * This function handles the complete flow of securely transferring a secret from an auth domain
 * to the client application without the auth domain ever knowing the client's private key.
 *
 * The flow works as follows:
 * 1. On first call: Generates a key pair, stores the private key locally, and redirects to the auth domain
 *    with the public key.
 * 2. On return from auth domain: Extracts the encrypted secret from the URL fragment, decrypts it
 *    using the stored private key, and stores the decrypted secret in localStorage.
 *
 * @param authUrl - The URL of the authentication domain that will provide the encrypted secret.
 *                  This URL should handle the public key and return the encrypted secret.
 *
 * @throws {Error} If key generation fails during the initial flow
 *
 * @example
 * ```typescript
 * // Initialize the client on page load
 * await initSecretClient('https://auth.example.com/zerokey');
 *
 * // Listen for when the secret is ready
 * window.addEventListener('zerokey:ready', () => {
 *   const secret = getSecret();
 *   console.log('Secret is now available:', secret);
 * });
 * ```
 *
 * @fires zerokey:ready - Fired when the secret has been successfully decrypted and stored
 */
export async function initSecretClient(authUrl: string): Promise<void> {
  // Check if we're returning from auth
  if (isReturningFromAuth()) {
    const { secret: encryptedSecret, state } = parseFragment();
    clearFragment();

    if (!encryptedSecret) {
      console.error('No encrypted secret in URL fragment');
      return;
    }

    // Get pending key
    const pending = getPendingKey();
    if (!pending) {
      console.error('No pending key found or key expired');
      // Could restart the flow here
      return;
    }

    // Verify state matches
    if (pending.state !== state) {
      console.error('State mismatch - possible CSRF');
      clearPendingKey();
      return;
    }

    try {
      // Deserialize and decrypt
      const privateKey = await deserializePrivateKey(pending.privateKey);
      const decryptedSecret = await decryptWithPrivateKey(encryptedSecret, privateKey);

      // Store the decrypted secret
      localStorage.setItem(STORAGE_KEY_SECRET, decryptedSecret);

      // Clean up
      clearPendingKey();

      // Emit event for app to know secret is ready
      window.dispatchEvent(new Event('zerokey:ready'));
    } catch (error) {
      console.error('Failed to decrypt secret:', error);
      clearPendingKey();
      // Could restart the flow here
    }
  } else {
    // Starting new flow
    try {
      // Generate new keypair
      const { publicKey, privateKey } = await generateKeyPair();

      // Generate state for CSRF protection
      const state = crypto.randomUUID();

      // Serialize and store private key
      const serializedPrivateKey = await serializePrivateKey(privateKey);
      storePendingKey(serializedPrivateKey, state);

      // Build auth URL with parameters
      const url = new URL(authUrl);
      url.searchParams.set('publicKey', publicKey);
      url.searchParams.set('redirect', window.location.href);
      url.searchParams.set('state', state);

      // Redirect to auth domain
      window.location.href = url.toString();
    } catch (error) {
      console.error('Failed to initiate secret transfer:', error);
      throw error;
    }
  }
}

/**
 * Retrieves the decrypted secret from localStorage.
 *
 * This function should be called after the 'zerokey:ready' event has been fired,
 * indicating that the secret has been successfully decrypted and stored.
 *
 * @returns The decrypted secret string if available, or null if no secret has been stored yet
 *          or if the authentication flow hasn't completed.
 *
 * @example
 * ```typescript
 * // Get the secret after initialization
 * const secret = getSecret();
 * if (secret) {
 *   // Use the secret for API authentication
 *   fetch('/api/data', {
 *     headers: {
 *       'Authorization': `Bearer ${secret}`
 *     }
 *   });
 * } else {
 *   console.log('Secret not yet available');
 * }
 * ```
 */
export function getSecret(): string | null {
  return localStorage.getItem(STORAGE_KEY_SECRET);
}

/**
 * Clears the stored secret and any pending authentication data from localStorage.
 *
 * This function should be called when:
 * - The user logs out
 * - The secret expires or becomes invalid
 * - You need to restart the authentication flow
 *
 * It removes both the decrypted secret and any pending key data that might be
 * waiting for the authentication flow to complete.
 *
 * @example
 * ```typescript
 * // Clear the secret on logout
 * function logout() {
 *   clearSecret();
 *   // Redirect to login page or reinitialize
 *   window.location.href = '/login';
 * }
 *
 * // Or clear and restart the flow
 * clearSecret();
 * await initSecretClient('https://auth.example.com/zerokey');
 * ```
 */
export function clearSecret(): void {
  localStorage.removeItem(STORAGE_KEY_SECRET);
  clearPendingKey();
}
