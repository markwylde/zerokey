import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = 3001;

// Serve static files from the root directory
app.use(express.static(join(__dirname, '../..')));

// Serve the app test page
app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>App Domain - Zerokey Test</title>
  <meta charset="utf-8">
</head>
<body>
  <h1>App Domain (localhost:3001)</h1>
  <div id="status">Ready</div>
  <button id="requestSecret">Request Secret from Auth Domain</button>
  <button id="getSecret">Get Current Secret</button>
  <button id="clearSecret">Clear Secret</button>
  <div id="result"></div>

  <script type="module">
    import { initSecretClient, getSecret, clearSecret } from '/client.js';

    const statusEl = document.getElementById('status');
    const resultEl = document.getElementById('result');

    // Listen for secret ready event
    window.addEventListener('zerokey:ready', () => {
      statusEl.textContent = 'Secret received!';
      const secret = getSecret();
      resultEl.textContent = 'Secret: ' + secret;
    });

    // Check if returning from auth
    if (window.location.hash) {
      statusEl.textContent = 'Processing return from auth...';
      initSecretClient('http://localhost:3002');
    }

    document.getElementById('requestSecret').addEventListener('click', async () => {
      statusEl.textContent = 'Redirecting to auth domain...';
      await initSecretClient('http://localhost:3002');
    });

    document.getElementById('getSecret').addEventListener('click', () => {
      const secret = getSecret();
      resultEl.textContent = secret ? 'Secret: ' + secret : 'No secret stored';
    });

    document.getElementById('clearSecret').addEventListener('click', () => {
      clearSecret();
      resultEl.textContent = 'Secret cleared';
    });
  </script>
</body>
</html>
  `);
});

app.listen(PORT, () => {
  console.log(`App server running at http://localhost:${PORT}`);
});
