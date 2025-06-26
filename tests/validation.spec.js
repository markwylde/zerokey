import { expect, test } from '@playwright/test';

test.describe('Zerokey Domain Validation', () => {
  const APP_URL = 'http://localhost:3001';
  const AUTH_URL = 'http://localhost:3002';
  const MALICIOUS_URL = 'http://malicious.com';

  test.beforeEach(async ({ context }) => {
    await context.clearCookies();
    await context.clearPermissions();
  });

  test('rejects unauthorized domains with validateCallbackUrl', async ({ page }) => {
    // Create auth page with validation
    await page.goto(`${AUTH_URL}/validation-test.html`);
    
    // Check that the page loaded correctly
    await expect(page.locator('h1')).toContainText('Validation Test');
    
    // Try to request with unauthorized domain
    const publicKey = '-----BEGIN PUBLIC KEY-----test-key-----END PUBLIC KEY-----';
    const state = 'test-state';
    
    // Navigate with malicious redirect URL
    await page.goto(`${AUTH_URL}/validation-test.html?publicKey=${encodeURIComponent(publicKey)}&redirect=${encodeURIComponent(MALICIOUS_URL)}&state=${state}`);
    
    // Verify error is shown
    await expect(page.locator('#status')).toContainText('Redirect URL failed custom validation');
  });

  test('allows authorized domains with validateCallbackUrl', async ({ page }) => {
    // Create auth page with validation
    await page.goto(`${AUTH_URL}/validation-test.html`);
    
    // Check that the page loaded correctly
    await expect(page.locator('h1')).toContainText('Validation Test');
    
    // Try to request with authorized domain
    const publicKey = '-----BEGIN PUBLIC KEY-----test-key-----END PUBLIC KEY-----';
    const state = 'test-state';
    
    // Navigate with allowed redirect URL
    await page.goto(`${AUTH_URL}/validation-test.html?publicKey=${encodeURIComponent(publicKey)}&redirect=${encodeURIComponent(APP_URL)}&state=${state}`);
    
    // Verify success
    await expect(page.locator('#status')).toContainText('Secret request received!');
  });

  test('validation function receives correct URL', async ({ page }) => {
    // This test verifies the URL passed to validateCallbackUrl is correct
    await page.goto(`${AUTH_URL}/validation-logging.html`);
    
    const testUrl = 'https://example.com/callback?foo=bar';
    const publicKey = '-----BEGIN PUBLIC KEY-----test-key-----END PUBLIC KEY-----';
    const state = 'test-state';
    
    await page.goto(`${AUTH_URL}/validation-logging.html?publicKey=${encodeURIComponent(publicKey)}&redirect=${encodeURIComponent(testUrl)}&state=${state}`);
    
    // Check that the logged URL matches what was passed
    const loggedUrl = await page.locator('#logged-url').textContent();
    expect(loggedUrl).toBe(testUrl);
  });
});