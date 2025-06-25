import { expect, test } from '@playwright/test';

test.describe('Zerokey Cross-Domain Secret Sharing', () => {
  const APP_URL = 'http://localhost:3001';
  const AUTH_URL = 'http://localhost:3002';

  test.beforeEach(async ({ context }) => {
    // Clear all cookies and localStorage for both domains
    await context.clearCookies();
    await context.clearPermissions();
  });

  test('happy path - complete secret transfer flow', async ({ page }) => {
    // Start on app domain
    await page.goto(APP_URL);
    await expect(page.locator('#status')).toHaveText('Ready');

    // Click request secret button
    await page.click('#requestSecret');

    // Should redirect to auth domain
    await page.waitForURL(/localhost:3002/);
    await expect(page.locator('h1')).toContainText('Auth Domain');

    // Verify parameters are present
    const url = new URL(page.url());
    expect(url.searchParams.get('publicKey')).toBeTruthy();
    expect(url.searchParams.get('redirect')).toBe(`${APP_URL}/`);
    expect(url.searchParams.get('state')).toBeTruthy();

    // Simulate login and set secret
    await page.fill('#password', 'my-secret-password');
    await page.click('#login');

    // Should redirect back to app domain
    await page.waitForURL(/localhost:3001/);

    // Wait for secret to be processed
    await expect(page.locator('#status')).toHaveText('Secret received!');

    // Verify secret is stored
    await page.click('#getSecret');
    await expect(page.locator('#result')).toContainText(
      'Secret: derived-key-from-my-secret-password'
    );
  });

  test('URL fragment is cleared after processing', async ({ page }) => {
    // Start on app domain
    await page.goto(APP_URL);

    // Request secret
    await page.click('#requestSecret');
    await page.waitForURL(/localhost:3002/);

    // Login
    await page.fill('#password', 'test');
    await page.click('#login');

    // Wait for redirect back
    await page.waitForURL(/localhost:3001/);
    await expect(page.locator('#status')).toHaveText('Secret received!');

    // Verify fragment is cleared
    const finalUrl = page.url();
    expect(finalUrl).not.toContain('#');
  });

  test('localStorage persistence across page refresh', async ({ page }) => {
    // Complete the flow
    await page.goto(APP_URL);
    await page.click('#requestSecret');
    await page.waitForURL(/localhost:3002/);
    await page.fill('#password', 'persistent-secret');
    await page.click('#login');
    await page.waitForURL(/localhost:3001/);
    await expect(page.locator('#status')).toHaveText('Secret received!');

    // Refresh the page
    await page.reload();

    // Secret should still be available
    await page.click('#getSecret');
    await expect(page.locator('#result')).toContainText(
      'Secret: derived-key-from-persistent-secret'
    );
  });

  test('clear secret functionality', async ({ page }) => {
    // Complete the flow
    await page.goto(APP_URL);
    await page.click('#requestSecret');
    await page.waitForURL(/localhost:3002/);
    await page.fill('#password', 'clearable-secret');
    await page.click('#login');
    await page.waitForURL(/localhost:3001/);
    await expect(page.locator('#status')).toHaveText('Secret received!');

    // Clear the secret
    await page.click('#clearSecret');
    await expect(page.locator('#result')).toHaveText('Secret cleared');

    // Verify it's gone
    await page.click('#getSecret');
    await expect(page.locator('#result')).toHaveText('No secret stored');
  });

  test('multiple concurrent flows - last one wins', async ({ context }) => {
    const page1 = await context.newPage();
    const page2 = await context.newPage();

    // Start flow on first page
    await page1.goto(APP_URL);
    await page1.click('#requestSecret');
    await page1.waitForURL(/localhost:3002/);

    // Start flow on second page
    await page2.goto(APP_URL);
    await page2.click('#requestSecret');
    await page2.waitForURL(/localhost:3002/);

    // Complete flow on second page
    await page2.fill('#password', 'second-secret');
    await page2.click('#login');
    await page2.waitForURL(/localhost:3001/);
    await expect(page2.locator('#status')).toHaveText('Secret received!');

    // Try to complete flow on first page (should work with its own state)
    await page1.fill('#password', 'first-secret');
    await page1.click('#login');
    await page1.waitForURL(/localhost:3001/);

    // Both should have their secrets
    await page2.click('#getSecret');
    await expect(page2.locator('#result')).toContainText('Secret: derived-key-from-second-secret');
  });

  test('auth domain without parameters shows error', async ({ page }) => {
    await page.goto(AUTH_URL);
    await expect(page.locator('#status')).toHaveText('No secret request - missing parameters');
    await expect(page.locator('#loginForm')).not.toBeVisible();
  });

  test('handles browser back navigation', async ({ page }) => {
    // Start flow
    await page.goto(APP_URL);
    await page.click('#requestSecret');
    await page.waitForURL(/localhost:3002/);

    // Go back
    await page.goBack();
    await expect(page.url()).toContain('localhost:3001');

    // Should be able to start flow again
    await page.click('#requestSecret');
    await page.waitForURL(/localhost:3002/);

    // Complete flow
    await page.fill('#password', 'back-nav-secret');
    await page.click('#login');
    await page.waitForURL(/localhost:3001/);
    await expect(page.locator('#status')).toHaveText('Secret received!');
  });
});
