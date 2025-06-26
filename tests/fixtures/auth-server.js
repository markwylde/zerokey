import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = 3002;

// Serve static files from the root directory
app.use(express.static(join(__dirname, '../..')));

// Serve validation test pages
app.get('/validation-test.html', (req, res) => {
  res.sendFile(join(__dirname, 'validation-test.html'));
});

app.get('/validation-logging.html', (req, res) => {
  res.sendFile(join(__dirname, 'validation-logging.html'));
});

// Serve the auth test page
app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Auth Domain - Zerokey Test</title>
  <meta charset="utf-8">
</head>
<body>
  <h1>Auth Domain (localhost:3002)</h1>
  <div id="status">Waiting for secret request...</div>
  
  <div id="loginForm">
    <h2>Simulate Login</h2>
    <input type="password" id="password" placeholder="Enter password" value="test-password">
    <button id="login">Login and Send Secret</button>
  </div>

  <div id="params"></div>

  <script type="module">
    import { initSecretServer, setSecret } from '/server.js';

    const statusEl = document.getElementById('status');
    const paramsEl = document.getElementById('params');
    const loginForm = document.getElementById('loginForm');

    // Parse and display parameters
    const params = new URLSearchParams(window.location.search);
    const publicKey = params.get('publicKey');
    const redirect = params.get('redirect');
    const state = params.get('state');

    if (publicKey && redirect && state) {
      statusEl.textContent = 'Secret request received!';
      paramsEl.innerHTML = \`
        <h3>Request Parameters:</h3>
        <p>Public Key: \${publicKey.substring(0, 20)}...</p>
        <p>Redirect: \${redirect}</p>
        <p>State: \${state}</p>
      \`;

      // Initialize the server
      initSecretServer();

      document.getElementById('login').addEventListener('click', () => {
        const password = document.getElementById('password').value;
        
        // Simulate deriving encryption key from password
        const encryptionKey = 'derived-key-from-' + password;
        
        statusEl.textContent = 'Encrypting and redirecting...';
        
        // Set the secret (this will trigger redirect)
        setSecret(encryptionKey);
      });
    } else {
      statusEl.textContent = 'No secret request - missing parameters';
      loginForm.style.display = 'none';
    }
  </script>
</body>
</html>
  `);
});

app.listen(PORT, () => {
  console.log(`Auth server running at http://localhost:${PORT}`);
});
