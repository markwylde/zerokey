/**
 * @module server
 * 
 * Server-side implementation for the zero-knowledge secret sharing system.
 * 
 * This module provides functions to create a secure secret server that can share
 * secrets (like API keys or tokens) with requesting applications without either party
 * having access to both the encryption key and the plaintext secret.
 * 
 * The flow works as follows:
 * 1. The requesting app generates an RSA keypair and keeps the private key
 * 2. The app redirects the user to the secret server with the public key
 * 3. The secret server authenticates the user and determines the secret to share
 * 4. The secret is encrypted client-side with the public key
 * 5. The user is redirected back with the encrypted secret in the URL fragment
 * 6. The requesting app decrypts the secret with its private key
 * 
 * Security properties:
 * - The secret server never sees the private key
 * - The requesting app never sees the plaintext secret on the server
 * - The encrypted secret is passed via URL fragment (never sent to servers)
 * - CSRF protection via state parameter
 * 
 * @example
 * ```typescript
 * // In your secret server's client-side code:
 * import { initSecretServer, setSecret } from 'zerokey/server';
 * 
 * // Initialize on page load
 * initSecretServer();
 * 
 * // After user authentication, set the secret
 * const apiKey = await getUserApiKey(userId);
 * setSecret(apiKey);
 * ```
 */
import { encryptWithPublicKey } from './crypto.js';

/**
 * Stores the secret temporarily if `setSecret()` is called before `initSecretServer()`.
 * This allows the secret to be set before the query parameters are parsed and validated.
 * @internal
 */
let pendingSecret: string | null = null;

/**
 * Tracks whether the secret server has been initialized to prevent duplicate initialization.
 * @internal
 */
let isInitialized = false;

/**
 * Query parameters expected by the zero-knowledge secret server.
 * These parameters are passed by the requesting application to configure the secret sharing flow.
 */
interface QueryParams {
  publicKey: string | null;
  redirect: string | null;
  state: string | null;
}

/**
 * Validated and required parameters for the zero-knowledge secret sharing flow.
 * These are stored globally after validation for use during the secret transfer process.
 */
interface ZerokeyParams {
  publicKey: string;
  redirect: string;
  state: string;
}

/**
 * Global window extension to store validated zerokey parameters.
 * This allows the parameters to persist between initialization and secret setting.
 */
declare global {
  interface Window {
    zerokeyParams?: ZerokeyParams;
  }
}

/**
 * Parses URL query parameters from the current window location.
 * Extracts the publicKey, redirect, and state parameters needed for the zero-knowledge secret sharing flow.
 * 
 * @returns {QueryParams} An object containing the parsed query parameters
 * @returns {string | null} QueryParams.publicKey - The RSA public key for encrypting the secret
 * @returns {string | null} QueryParams.redirect - The URL to redirect to after encryption
 * @returns {string | null} QueryParams.state - The state parameter for CSRF protection
 * 
 * @example
 * // URL: https://secret-server.com?publicKey=...&redirect=https://app.com&state=abc123
 * const params = parseQueryParams();
 * // Returns: { publicKey: "...", redirect: "https://app.com", state: "abc123" }
 */
function parseQueryParams(): QueryParams {
  const params = new URLSearchParams(window.location.search);
  return {
    publicKey: params.get('publicKey'),
    redirect: params.get('redirect'),
    state: params.get('state')
  };
}

/**
 * Validates that a redirect URL is safe to use.
 * Ensures the URL is properly formatted and uses either HTTP or HTTPS protocol.
 * This prevents potential security issues with malicious redirect URLs.
 * 
 * @param {string} url - The redirect URL to validate
 * @returns {boolean} True if the URL is valid and safe, false otherwise
 * 
 * @example
 * isValidRedirect('https://app.com/callback'); // returns true
 * isValidRedirect('javascript:alert(1)'); // returns false
 * isValidRedirect('file:///etc/passwd'); // returns false
 */
function isValidRedirect(url: string): boolean {
  try {
    const parsedUrl = new URL(url);
    // Ensure it's http or https
    return parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Encrypts the secret with the provided public key and redirects to the specified URL.
 * The encrypted secret is passed in the URL fragment (hash) to ensure it's never sent to the server.
 * This maintains the zero-knowledge property of the system.
 * 
 * @param {string} secret - The plaintext secret to encrypt and transfer
 * @param {string} publicKey - The RSA public key (in PEM format) to encrypt the secret
 * @param {string} redirectUrl - The URL to redirect to after encryption
 * @param {string} state - The state parameter for CSRF protection and request correlation
 * @returns {Promise<void>} A promise that resolves when the redirect is performed
 * 
 * @throws {Error} May throw if encryption fails or URL parsing fails
 * 
 * @example
 * await performRedirect(
 *   'my-secret-api-key',
 *   '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgk...',
 *   'https://app.com/callback',
 *   'unique-state-123'
 * );
 * // Redirects to: https://app.com/callback#secret=encrypted...&state=unique-state-123
 */
async function performRedirect(
  secret: string,
  publicKey: string,
  redirectUrl: string,
  state: string
): Promise<void> {
  try {
    // Encrypt the secret
    const encryptedSecret = await encryptWithPublicKey(secret, publicKey);

    // Build redirect URL with fragment
    const url = new URL(redirectUrl);
    const fragment = new URLSearchParams({
      secret: encryptedSecret,
      state: state
    }).toString();

    // Redirect with fragment (never sent to server)
    window.location.href = `${url.origin}${url.pathname}${url.search}#${fragment}`;
  } catch (error) {
    console.error('Failed to encrypt and redirect:', error);
    // Redirect back with error
    const url = new URL(redirectUrl);
    window.location.href = `${url.origin}${url.pathname}${url.search}#error=encryption_failed&state=${state}`;
  }
}

/**
 * Initializes the zero-knowledge secret server handler.
 * This function should be called when the secret server page loads.
 * It parses the query parameters, validates them, and prepares the system to receive a secret.
 * 
 * The function expects the following query parameters:
 * - publicKey: RSA public key for encrypting the secret
 * - redirect: URL to redirect to after processing
 * - state: CSRF protection state parameter
 * 
 * If a secret has already been set via `setSecret()` before initialization,
 * it will immediately process and redirect with the encrypted secret.
 * 
 * @returns {void}
 * 
 * @throws {Error} Logs errors if required parameters are missing or invalid
 * 
 * @example
 * // On page load of the secret server:
 * import { initSecretServer } from 'zerokey/server';
 * 
 * // Initialize when DOM is ready
 * document.addEventListener('DOMContentLoaded', () => {
 *   initSecretServer();
 * });
 * 
 * @example
 * // URL: https://secrets.example.com?publicKey=...&redirect=https://app.com&state=abc123
 * initSecretServer(); // Parses params and prepares for secret input
 */
export function initSecretServer(): void {
  if (isInitialized) {
    console.warn('Secret server already initialized');
    return;
  }

  isInitialized = true;

  // Parse parameters on initialization
  const { publicKey, redirect, state } = parseQueryParams();

  // Validate required parameters
  if (!publicKey || !redirect || !state) {
    console.error('Missing required parameters');
    return;
  }

  if (!isValidRedirect(redirect)) {
    console.error('Invalid redirect URL');
    return;
  }

  // Store parameters for later use
  window.zerokeyParams = { publicKey, redirect, state };

  // If secret is already pending, process it
  if (pendingSecret) {
    performRedirect(pendingSecret, publicKey, redirect, state);
  }
}

/**
 * Sets the secret that will be encrypted and transferred to the requesting application.
 * This function should be called after the user has authenticated and the server
 * has determined what secret (e.g., API key, token) to share.
 * 
 * If `initSecretServer()` has already been called and valid parameters are present,
 * this will immediately encrypt the secret and redirect. Otherwise, it stores the
 * secret until initialization occurs.
 * 
 * The secret is encrypted client-side using the public key provided in the query parameters,
 * ensuring the secret server never sees the public key and the requesting app never sees
 * the plaintext secret - maintaining zero-knowledge properties.
 * 
 * @param {string} secret - The plaintext secret to be encrypted and transferred
 * @returns {void}
 * 
 * @throws {Error} Logs an error if the secret is empty
 * 
 * @example
 * // After user authentication:
 * const userApiKey = await generateApiKeyForUser(userId);
 * setSecret(userApiKey);
 * // User is automatically redirected with encrypted secret
 * 
 * @example
 * // In a form submission handler:
 * document.getElementById('secret-form').addEventListener('submit', (e) => {
 *   e.preventDefault();
 *   const secret = document.getElementById('secret-input').value;
 *   setSecret(secret);
 * });
 */
export function setSecret(secret: string): void {
  if (!secret) {
    console.error('Secret cannot be empty');
    return;
  }

  pendingSecret = secret;

  // If already initialized with params, perform redirect
  if (window.zerokeyParams) {
    const { publicKey, redirect, state } = window.zerokeyParams;
    performRedirect(secret, publicKey, redirect, state);
  }
}
