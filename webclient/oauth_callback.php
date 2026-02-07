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
 * exchanges the authorization code for tokens using the SDK's OAuthClient,
 * stores them, and redirects back to the main UI.
 */

declare(strict_types=1);

require_once __DIR__ . '/common.php';

use Mcp\Client\Auth\AuthorizationRequest;
use Mcp\Client\Auth\OAuthConfiguration;
use Mcp\Client\Auth\OAuthClient;
use Mcp\Client\Auth\OAuthException;
use Mcp\Client\Auth\Registration\ClientCredentials;

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
        if (isset($flow['authRequest']['state']) && $flow['authRequest']['state'] === $state) {
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

    // Restore AuthorizationRequest from session
    if (!isset($pendingFlow['authRequest'])) {
        $logger->error('Missing authorization request data');
        unset($_SESSION['oauth_pending'][$serverId]);
        redirectToMain(false, 'Missing authorization request data. Please try connecting again.');
    }

    try {
        $authRequest = AuthorizationRequest::fromArray($pendingFlow['authRequest']);
    } catch (\InvalidArgumentException $e) {
        $logger->error('Invalid authorization request data', ['error' => $e->getMessage()]);
        unset($_SESSION['oauth_pending'][$serverId]);
        redirectToMain(false, 'Invalid authorization request data');
    }

    // Create OAuthConfiguration for the SDK
    $tokenStorage = createTokenStorage();
    $clientCredentials = new ClientCredentials(
        clientId: $authRequest->clientId,
        clientSecret: $authRequest->clientSecret,
        tokenEndpointAuthMethod: $authRequest->tokenEndpointAuthMethod
    );

    $oauthConfig = new OAuthConfiguration(
        tokenStorage: $tokenStorage,
        clientCredentials: $clientCredentials
    );

    $oauthClient = new OAuthClient($oauthConfig, $logger);

    // Exchange code for tokens using SDK
    try {
        $tokens = $oauthClient->exchangeCodeForTokens($authRequest, $code);
        $logger->info('Tokens obtained successfully via SDK');
        $resourceUrl = $authRequest->resourceUrl;
    } catch (OAuthException $e) {
        $logger->error('Token exchange failed: ' . $e->getMessage());
        unset($_SESSION['oauth_pending'][$serverId]);
        redirectToMain(false, 'Token exchange failed: ' . $e->getMessage());
    }

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
