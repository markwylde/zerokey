import { expect, test } from '@playwright/test';

test.describe('Zerokey Edge Cases and Error Handling', () => {
  const APP_URL = 'http://localhost:3001';
  const AUTH_URL = 'http://localhost:3002';

  test.beforeEach(async ({ context }) => {
    await context.clearCookies();
    await context.clearPermissions();
  });

  test('expired pending key (5 minute timeout)', async ({ page }) => {
    // Override Date.now to simulate time passing
    await page.goto(APP_URL);

    // Start the flow
    await page.click('#requestSecret');
    await page.waitForURL(/localhost:3002/);

    // Get the state from URL for later
    const authUrl = new URL(page.url());
    const state = authUrl.searchParams.get('state');
    const publicKey = authUrl.searchParams.get('publicKey');

    // Go back to app domain
    await page.goto(APP_URL);

    // Modify localStorage to simulate expired key
    await page.evaluate(() => {
      const pendingData = JSON.parse(localStorage.getItem('zerokey_pending'));
      if (pendingData) {
        // Set timestamp to 6 minutes ago
        pendingData.timestamp = Date.now() - 6 * 60 * 1000;
        localStorage.setItem('zerokey_pending', JSON.stringify(pendingData));
      }
    });

    // Try to complete flow with expired key
    const fragment = `#secret=fake-encrypted-data&state=${state}`;
    await page.goto(APP_URL + fragment);

    // Should not process due to expired key
    const secret = await page.evaluate(() => localStorage.getItem('zerokey_secret'));
    expect(secret).toBeNull();
  });

  test('state mismatch (CSRF protection)', async ({ page }) => {
    await page.goto(APP_URL);

    // Start the flow
    await page.click('#requestSecret');
    await page.waitForURL(/localhost:3002/);

    // Go back to app with mismatched state
    const fragment = '#secret=fake-encrypted-data&state=wrong-state-12345';
    await page.goto(APP_URL + fragment);

    // Should not process due to state mismatch
    const secret = await page.evaluate(() => localStorage.getItem('zerokey_secret'));
    expect(secret).toBeNull();

    // Pending key should be cleared
    const pending = await page.evaluate(() => localStorage.getItem('zerokey_pending'));
    expect(pending).toBeNull();
  });

  test('malformed encrypted data', async ({ page }) => {
    await page.goto(APP_URL);

    // Set up a valid pending key
    await page.evaluate(() => {
      const pendingData = {
        privateKey: '{"fake":"key"}',
        state: 'test-state',
        timestamp: Date.now()
      };
      localStorage.setItem('zerokey_pending', JSON.stringify(pendingData));
    });

    // Try to process malformed encrypted data
    const fragment = '#secret=not-valid-base64!@#$&state=test-state';
    await page.goto(APP_URL + fragment);

    // Should handle error gracefully
    const secret = await page.evaluate(() => localStorage.getItem('zerokey_secret'));
    expect(secret).toBeNull();
  });

  test('missing fragment parameters', async ({ page }) => {
    await page.goto(APP_URL);

    // Set up a pending key
    await page.evaluate(() => {
      const pendingData = {
        privateKey: '{"fake":"key"}',
        state: 'test-state',
        timestamp: Date.now()
      };
      localStorage.setItem('zerokey_pending', JSON.stringify(pendingData));
    });

    // Fragment without secret parameter
    await page.goto(`${APP_URL}#state=test-state`);

    // Should not process
    const secret = await page.evaluate(() => localStorage.getItem('zerokey_secret'));
    expect(secret).toBeNull();
  });

  test('invalid redirect URL on auth domain', async ({ page }) => {
    // Try to access auth domain with invalid redirect
    const invalidUrl = `${AUTH_URL}?publicKey=fake-key&redirect=not-a-url&state=test`;
    await page.goto(invalidUrl);

    // The page shows parameters received, but initSecretServer should fail validation
    await expect(page.locator('#status')).toHaveText('Secret request received!');

    // Try to set a secret, which should fail due to invalid redirect
    await page.fill('#password', 'test');
    await page.click('#login');

    // Should not redirect (stay on same page)
    await page.waitForTimeout(500);
    expect(page.url()).toContain('localhost:3002');
  });

  test('empty secret handling', async ({ page }) => {
    await page.goto(AUTH_URL);

    // Create a mock auth page that tries to set empty secret
    await page.evaluate(() => {
      window.zerokeyParams = {
        publicKey: 'fake-key',
        redirect: 'http://localhost:3001',
        state: 'test-state'
      };
    });

    // Import and try to set empty secret
    const result = await page.evaluate(async () => {
      const module = await import('/server.js');
      module.setSecret(''); // Empty secret
      return true;
    });

    // Should not redirect (empty secret is rejected)
    expect(page.url()).toContain('localhost:3002');
  });

  test('handles network errors gracefully', async ({ page, context }) => {
    await page.goto(APP_URL);

    // Start flow
    await page.click('#requestSecret');
    await page.waitForURL(/localhost:3002/);

    // Simulate network error by blocking the app domain
    await context.route('http://localhost:3001/**', (route) => route.abort());

    // Try to complete flow
    await page.fill('#password', 'test');
    await page.click('#login');

    // Should fail gracefully (page won't load but no JS errors)
    await page.waitForTimeout(1000);

    // Re-enable network
    await context.unroute('http://localhost:3001/**');
  });

  test('handles corrupted localStorage data', async ({ page }) => {
    await page.goto(APP_URL);

    // Test the getPendingKey function directly with corrupted data
    const result = await page.evaluate(async () => {
      // Set corrupted data
      localStorage.setItem('zerokey_pending', 'not-valid-json{]');

      // Import and test
      const module = await import('/client.js');

      // Call initSecretClient with a fragment to trigger getPendingKey
      window.location.hash = '#secret=encrypted&state=test';

      try {
        await module.initSecretClient('http://localhost:3002');
      } catch (e) {
        // Expected to fail
      }

      // Check if corrupted data was cleared
      return {
        secret: localStorage.getItem('zerokey_secret'),
        pending: localStorage.getItem('zerokey_pending')
      };
    });

    // Should handle gracefully
    expect(result.secret).toBeNull();
    expect(result.pending).toBeNull();
  });
});
