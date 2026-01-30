<?php

/**
 * Model Context Protocol SDK for PHP
 *
 * (c) 2025 Logiscape LLC <https://logiscape.com>
 *
 * Based on the Python SDK for the Model Context Protocol
 * https://github.com/modelcontextprotocol/python-sdk
 *
 * PHP conversion developed by:
 * - Josh Abbott
 * - Claude 3.5 Sonnet (Anthropic AI model)
 * - ChatGPT o1 pro mode
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @package    logiscape/mcp-sdk-php
 * @author     Josh Abbott <https://joshabbott.com>
 * @copyright  Logiscape LLC
 * @license    MIT License
 * @link       https://github.com/logiscape/mcp-sdk-php
 */

/**
 * OAuth 2.0 callback endpoint for the MCP Web Client.
 *
 * This endpoint receives the authorization callback from the OAuth provider,
 * exchanges the authorization code for tokens, stores them, and redirects
 * back to the main UI.
 */

declare(strict_types=1);

require_once __DIR__ . '/common.php';

use Mcp\Client\Auth\Token\TokenSet;

/**
 * Redirect to main page with status.
 */
function redirectToMain(bool $success, ?string $error = null, ?string $serverId = null): void {
    $params = [];
    if ($success) {
        $params['oauth_success'] = '1';
        if ($serverId) {
            $params['server_id'] = $serverId;
        }
    } else {
        $params['oauth_error'] = $error ?? 'Unknown error';
    }

    $query = http_build_query($params);
    header('Location: index.php?' . $query);
    exit;
}

try {
    // Check for OAuth error response
    if (isset($_GET['error'])) {
        $error = $_GET['error'];
        $errorDescription = $_GET['error_description'] ?? $error;
        $logger->warning('OAuth error received', [
            'error' => $error,
            'description' => $errorDescription,
        ]);
        redirectToMain(false, $errorDescription);
    }

    // Verify required parameters
    if (!isset($_GET['code']) || !isset($_GET['state'])) {
        $logger->error('Missing OAuth callback parameters');
        redirectToMain(false, 'Missing authorization code or state parameter');
    }

    $code = $_GET['code'];
    $state = $_GET['state'];

    // Validate state against session
    if (!isset($_SESSION['oauth_pending'])) {
        $logger->error('No pending OAuth flow in session');
        redirectToMain(false, 'No pending OAuth authorization. Please try connecting again.');
    }

    // Find the pending OAuth flow matching this state
    $pendingFlow = null;
    $serverId = null;
    foreach ($_SESSION['oauth_pending'] as $sid => $flow) {
        if ($flow['state'] === $state) {
            $pendingFlow = $flow;
            $serverId = $sid;
            break;
        }
    }

    if ($pendingFlow === null) {
        $logger->error('Invalid OAuth state parameter');
        redirectToMain(false, 'Invalid state parameter. This may be a CSRF attack or the session expired.');
    }

    // Check if the flow has expired (5 minute timeout)
    if (time() - $pendingFlow['startedAt'] > 300) {
        unset($_SESSION['oauth_pending'][$serverId]);
        $logger->error('OAuth flow expired');
        redirectToMain(false, 'Authorization flow expired. Please try connecting again.');
    }

    $logger->info('Processing OAuth callback', ['serverId' => $serverId]);

    // Exchange code for tokens
    $tokenEndpoint = $pendingFlow['tokenEndpoint'];
    $verifier = $pendingFlow['verifier'];
    $redirectUri = getCallbackUrl();
    $clientId = $pendingFlow['clientId'];
    $clientSecret = $pendingFlow['clientSecret'] ?? null;
    $resourceUrl = $pendingFlow['resourceUrl'];
    $issuer = $pendingFlow['issuer'] ?? null;

    // Build token request
    $tokenParams = [
        'grant_type' => 'authorization_code',
        'code' => $code,
        'redirect_uri' => $redirectUri,
        'code_verifier' => $verifier,
        'client_id' => $clientId,
    ];

    // Add resource indicator if available
    if (isset($pendingFlow['resource'])) {
        $tokenParams['resource'] = $pendingFlow['resource'];
    }

    // Add client secret if available
    if ($clientSecret !== null) {
        $tokenParams['client_secret'] = $clientSecret;
    }

    $logger->debug('Exchanging code for tokens', ['tokenEndpoint' => $tokenEndpoint]);

    // Make token request
    $ch = curl_init($tokenEndpoint);
    if ($ch === false) {
        throw new RuntimeException('Failed to initialize cURL for token request');
    }

    $headers = [
        'Content-Type: application/x-www-form-urlencoded',
        'Accept: application/json',
    ];

    // Use Basic auth if client secret is provided and not already in params
    if ($clientSecret !== null && !isset($tokenParams['client_secret'])) {
        $credentials = base64_encode($clientId . ':' . $clientSecret);
        $headers[] = "Authorization: Basic {$credentials}";
    }

    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query($tokenParams),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_SSL_VERIFYPEER => $pendingFlow['verifyTls'] ?? true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    curl_close($ch);

    if ($response === false) {
        $logger->error('Token request failed', ['error' => $curlError]);
        unset($_SESSION['oauth_pending'][$serverId]);
        redirectToMain(false, "Token request failed: {$curlError}");
    }

    $tokenData = json_decode($response, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        $logger->error('Invalid token response JSON', ['response' => $response]);
        unset($_SESSION['oauth_pending'][$serverId]);
        redirectToMain(false, 'Invalid response from authorization server');
    }

    // Check for error in token response
    if (isset($tokenData['error'])) {
        $error = $tokenData['error'];
        $description = $tokenData['error_description'] ?? $error;
        $logger->error('Token endpoint error', ['error' => $error, 'description' => $description]);
        unset($_SESSION['oauth_pending'][$serverId]);
        redirectToMain(false, $description);
    }

    if ($httpCode !== 200) {
        $logger->error('Token request failed with HTTP error', ['httpCode' => $httpCode]);
        unset($_SESSION['oauth_pending'][$serverId]);
        redirectToMain(false, "Token request failed with HTTP {$httpCode}");
    }

    if (!isset($tokenData['access_token'])) {
        $logger->error('Token response missing access_token');
        unset($_SESSION['oauth_pending'][$serverId]);
        redirectToMain(false, 'Token response missing access_token');
    }

    $logger->info('Successfully obtained access token');

    // Create TokenSet from response
    $tokens = TokenSet::fromTokenResponse($tokenData, $resourceUrl, $issuer);

    // Store tokens
    $tokenStorage = createTokenStorage();
    $tokenStorage->store($resourceUrl, $tokens);

    $logger->info('Tokens stored successfully');

    // Mark OAuth as complete and store necessary info for completing the connection
    $_SESSION['oauth_completed'][$serverId] = [
        'resourceUrl' => $resourceUrl,
        'httpConfig' => $pendingFlow['httpConfig'],
        'oauthConfig' => $pendingFlow['oauthConfig'],
        'completedAt' => time(),
    ];

    // Clean up pending flow
    unset($_SESSION['oauth_pending'][$serverId]);

    // Redirect back to main page with success
    redirectToMain(true, null, $serverId);

} catch (Throwable $e) {
    $logger->error('OAuth callback error', [
        'error' => $e->getMessage(),
        'trace' => $e->getTraceAsString(),
    ]);
    redirectToMain(false, 'An error occurred during authorization: ' . $e->getMessage());
}
