# Zerokey

A zero-knowledge cross-domain secret sharing library that enables secure transfer of secrets between different domains without the server ever seeing the secret. Uses ECDH asymmetric encryption to ensure complete privacy.

## Features

- 🔐 **Zero-Knowledge**: Server never sees the actual secret
- 🔗 **Cross-Domain**: Securely transfer secrets between different domains
- 🛡️ **ECDH Encryption**: Uses P-256 curve with AES-GCM for hybrid encryption
- 📦 **No Dependencies**: Uses only the Web Crypto API
- ⏱️ **Auto-Expiry**: Pending keys expire after 5 minutes
- 🎯 **CSRF Protection**: Built-in state parameter validation
- 🧪 **Well-Tested**: Comprehensive Playwright test suite

## Installation

```bash
npm install zerokey
```

## Quick Start

### On your app domain (app.example.com)

```javascript
import { initSecretClient, getSecret } from 'zerokey/client';

// Start the flow (usually on app load)
await initSecretClient('https://auth.example.com/secret');

// Later, when you need the secret
const encryptionKey = getSecret();
if (!encryptionKey) {
  // User hasn't authenticated yet
}
```

### On your auth domain (auth.example.com)

```javascript
import { initSecretServer, setSecret } from 'zerokey/server';

// Set up the handler
initSecretServer();

// After user logs in and you derive the key
const encryptionKey = deriveKeyFromPassword(password, salt);
setSecret(encryptionKey);
// This will automatically redirect back
```

## How It Works

1. **App domain** generates an ephemeral ECDH keypair
2. **App domain** redirects to auth domain with the public key
3. **Auth domain** encrypts the secret with the public key  
4. **Auth domain** redirects back with encrypted secret in URL fragment
5. **App domain** decrypts using the private key

The key insight is that URL fragments (`#`) are never sent to servers, ensuring the encrypted secret remains client-side only.

## API Reference

### Client API (`zerokey/client`)

#### `initSecretClient(authUrl: string): Promise<void>`

Initiates the secret transfer flow. If returning from auth domain, decrypts and stores the secret. Otherwise, generates a new keypair and redirects to the auth domain.

```javascript
await initSecretClient('https://auth.example.com/secret');
```

#### `getSecret(): string | null`

Retrieves the decrypted secret from localStorage.

```javascript
const secret = getSecret();
if (secret) {
  // Use the secret
}
```

#### `clearSecret(): void`

Clears the stored secret and any pending keys.

```javascript
clearSecret();
```

### Server API (`zerokey/server`)

#### `initSecretServer(options?: SecretServerOptions): void`

Initializes the server handler on the auth domain. Parses query parameters and prepares for secret transfer.

```javascript
// Basic usage
initSecretServer();

// With domain validation for enhanced security
initSecretServer({
  validateCallbackUrl: (url) => url.startsWith('https://myapp.com')
});
```

**Options:**
- `validateCallbackUrl?: (url: string) => boolean` - Optional callback to validate redirect URLs. This provides protection against unauthorized domains requesting secrets.

#### `setSecret(secret: string): void`

Sets the secret to be encrypted and transferred back to the app domain.

```javascript
// After user authenticates
const encryptionKey = deriveKey(password, salt);
setSecret(encryptionKey);
```

## Security Considerations

1. **URL Fragments**: The library uses URL fragments (`#`) which are never sent to servers
2. **One-Time Keys**: Each transfer uses a fresh ephemeral keypair
3. **Auto-Expiry**: Pending keys expire after 5 minutes
4. **CSRF Protection**: State parameter prevents replay attacks
5. **HTTPS Required**: Always use HTTPS in production
6. **Domain Validation**: Use `validateCallbackUrl` to restrict which domains can request secrets

### Preventing Unauthorized Access

By default, any domain can request a secret from your auth server. To prevent malicious sites from obtaining secrets, use the `validateCallbackUrl` option:

```javascript
// Only allow your specific app domain
initSecretServer({
  validateCallbackUrl: (url) => url.startsWith('https://myapp.com')
});

// Allow multiple trusted domains
initSecretServer({
  validateCallbackUrl: (url) => {
    const trustedDomains = [
      'https://app.example.com',
      'https://staging.example.com',
      'http://localhost:3000' // for development only - always use HTTPS in production
    ];
    return trustedDomains.some(domain => url.startsWith(domain));
  }
});
```

This prevents scenarios where `dodgysite.com` could redirect users to your auth server and attempt to obtain their secrets.

## Testing

The library includes comprehensive Playwright tests that verify the complete cross-domain flow.

```bash
# Install dependencies
npm install

# Run tests
npm test

# Run tests in headed mode (see the browser)
npm run test:headed

# Debug tests
npm run test:debug
```

### Test Coverage

- ✅ Happy path flow
- ✅ URL fragment handling
- ✅ LocalStorage persistence  
- ✅ Key expiration (5 min timeout)
- ✅ CSRF protection
- ✅ Error handling
- ✅ Browser navigation
- ✅ Multiple concurrent flows

## Browser Support

Requires browsers with Web Crypto API support:
- Chrome 37+
- Firefox 34+
- Safari 11+
- Edge 79+

## Example Implementation

### Complete Auth Page

```html
<!DOCTYPE html>
<html>
<head>
  <title>Login - Auth Domain</title>
</head>
<body>
  <h1>Login</h1>
  <form id="loginForm">
    <input type="email" id="email" required>
    <input type="password" id="password" required>
    <button type="submit">Login</button>
  </form>

  <script type="module">
    import { initSecretServer, setSecret } from 'zerokey/server';
    
    // Initialize on page load
    initSecretServer();
    
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const email = document.getElementById('email').value;
      const password = document.getElementById('password').value;
      
      // Authenticate user (your logic here)
      const { salt, iterations } = await authenticateUser(email, password);
      
      // Derive encryption key from password
      const encryptionKey = await deriveKey(password, salt, iterations);
      
      // Send the key back encrypted
      setSecret(encryptionKey);
    });
  </script>
</body>
</html>
```

### Complete App Page

```html
<!DOCTYPE html>
<html>
<head>
  <title>My App</title>
</head>
<body>
  <div id="app">
    <h1>Welcome to My App</h1>
    <div id="status">Loading...</div>
  </div>

  <script type="module">
    import { initSecretClient, getSecret } from 'zerokey/client';
    
    // Check for existing secret or start flow
    async function initialize() {
      const secret = getSecret();
      
      if (secret) {
        // User is authenticated
        document.getElementById('status').textContent = 'Authenticated';
        initializeApp(secret);
      } else {
        // Need to authenticate
        document.getElementById('status').textContent = 'Redirecting to login...';
        await initSecretClient('https://auth.example.com/login');
      }
    }
    
    // Listen for secret ready event
    window.addEventListener('zerokey:ready', () => {
      const secret = getSecret();
      document.getElementById('status').textContent = 'Authenticated';
      initializeApp(secret);
    });
    
    initialize();
  </script>
</body>
</html>
```

## Advanced Usage

### Custom Expiration Time

While the default 5-minute expiration is recommended, you can implement custom logic:

```javascript
// In your app, before calling initSecretClient
const CUSTOM_EXPIRY = 10 * 60 * 1000; // 10 minutes

// Override the storage method
const originalSetItem = localStorage.setItem;
localStorage.setItem = function(key, value) {
  if (key === 'zerokey_pending') {
    const data = JSON.parse(value);
    data.customExpiry = Date.now() + CUSTOM_EXPIRY;
    value = JSON.stringify(data);
  }
  originalSetItem.call(this, key, value);
};
```

### Multiple Secrets

You can transfer multiple secrets by encoding them:

```javascript
// On auth domain
const secrets = {
  encryptionKey: derivedKey,
  apiToken: userApiToken,
  refreshToken: refreshToken
};
setSecret(JSON.stringify(secrets));

// On app domain
const secretsJson = getSecret();
const secrets = JSON.parse(secretsJson);
```

## Troubleshooting

### Secret not received

1. Check browser console for errors
2. Verify both domains use HTTPS in production
3. Ensure query parameters are properly encoded
4. Check if pending key expired (5 min timeout)

### CORS issues

This library doesn't make any cross-origin requests. All communication happens via redirects and URL parameters.

### localStorage not available

The library requires localStorage. For Safari private browsing, consider using a fallback to sessionStorage.

## License

MIT

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for your changes
4. Ensure all tests pass (`npm test`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request