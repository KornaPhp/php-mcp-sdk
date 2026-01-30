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
 * Endpoint for managing MCP server connections
 *
 * Handles:
 * - POST: Create new connection to MCP server (stdio or HTTP)
 * - DELETE: Close existing connection
 */

require_once __DIR__ . '/common.php';

/**
 * Basic security checks for command paths (stdio connections)
 */
function validateCommand(string $command): bool {
    // Block obviously dangerous commands
    $dangerousCommands = ['rm', 'sudo', 'chmod', 'chown', '>;', '|'];
    foreach ($dangerousCommands as $dangerous) {
        if (stripos($command, $dangerous) !== false) {
            return false;
        }
    }

    // Common MCP server executables
    $commonExecutables = ['node', 'npm', 'npx', 'uvx', 'python', 'python3', 'pip', 'php', 'uvicorn'];

    // Check if it's one of the common executables or a path to a file
    $commandBase = basename($command);
    if (in_array($commandBase, $commonExecutables)) {
        return true;
    }

    // If it's a file path, check that it exists and is executable
    if (file_exists($command)) {
        return is_executable($command);
    }

    // If command contains path separators but file doesn't exist, reject it
    if (strpos($command, '/') !== false || strpos($command, '\\') !== false) {
        return false;
    }

    // Allow other commands to support custom server executables
    return true;
}

/**
 * Validate HTTP URL
 */
function validateHttpUrl(string $url): bool {
    $parsed = parse_url($url);
    if ($parsed === false) {
        return false;
    }

    // Must have scheme and host
    if (!isset($parsed['scheme']) || !isset($parsed['host'])) {
        return false;
    }

    // Must be http or https
    $scheme = strtolower($parsed['scheme']);
    if (!in_array($scheme, ['http', 'https'], true)) {
        return false;
    }

    return true;
}

// Only allow POST and DELETE methods
$method = $_SERVER['REQUEST_METHOD'];
if (!in_array($method, ['POST', 'DELETE'])) {
    sendJsonResponse([
        'success' => false,
        'error' => 'Method not allowed'
    ], 405);
}

try {
    if ($method === 'POST') {
        // Handle new connection request
        $data = getJsonRequestBody();

        // Check for special actions
        $action = $data['action'] ?? 'connect';

        if ($action === 'complete_oauth') {
            // Complete OAuth connection after callback
            if (empty($data['serverId'])) {
                sendJsonResponse([
                    'success' => false,
                    'error' => 'Server ID is required to complete OAuth connection'
                ], 400);
            }

            $logger->info('Completing OAuth connection', ['serverId' => $data['serverId']]);

            $result = $mcpClient->completeOAuthConnection($data['serverId']);

            sendJsonResponse([
                'success' => true,
                'data' => [
                    'sessionId' => $result['sessionId'],
                    'capabilities' => $result['capabilities'],
                    'type' => $result['type'] ?? 'http'
                ],
                'logs' => getBufferedLogs($logger)
            ]);
        }

        // Determine connection type
        $type = $data['type'] ?? 'stdio';

        if ($type === 'http') {
            // HTTP connection
            if (empty($data['url'])) {
                sendJsonResponse([
                    'success' => false,
                    'error' => 'URL is required for HTTP connections'
                ], 400);
            }

            // Validate URL
            if (!validateHttpUrl($data['url'])) {
                sendJsonResponse([
                    'success' => false,
                    'error' => 'Invalid HTTP/HTTPS URL'
                ], 400);
            }

            // Build HTTP configuration
            $httpConfig = [
                'connectionTimeout' => floatval($data['connectionTimeout'] ?? 30),
                'readTimeout' => floatval($data['readTimeout'] ?? 60),
                'verifyTls' => $data['verifyTls'] ?? true,
                'headers' => $data['headers'] ?? '',
            ];

            // Validate timeouts
            if ($httpConfig['connectionTimeout'] < 1 || $httpConfig['connectionTimeout'] > 300) {
                sendJsonResponse([
                    'success' => false,
                    'error' => 'Connection timeout must be between 1 and 300 seconds'
                ], 400);
            }

            if ($httpConfig['readTimeout'] < 1 || $httpConfig['readTimeout'] > 600) {
                sendJsonResponse([
                    'success' => false,
                    'error' => 'Read timeout must be between 1 and 600 seconds'
                ], 400);
            }

            // Build OAuth configuration
            $oauthConfig = null;
            if (!empty($data['oauthEnabled'])) {
                $oauthConfig = [
                    'enabled' => true,
                    'clientId' => $data['oauthClientId'] ?? null,
                    'clientSecret' => $data['oauthClientSecret'] ?? null,
                ];
            }

            $logger->info('Attempting HTTP connection to MCP server', [
                'url' => $data['url'],
                'oauth' => $oauthConfig !== null ? 'enabled' : 'disabled'
            ]);

            // Attempt HTTP connection
            $result = $mcpClient->connectHttp($data['url'], $httpConfig, $oauthConfig);

            // Check if OAuth redirect is required
            if (!empty($result['requiresOAuth'])) {
                sendJsonResponse([
                    'success' => true,
                    'data' => [
                        'requiresOAuth' => true,
                        'authUrl' => $result['authUrl'],
                        'serverId' => $result['serverId'],
                        'message' => $result['message']
                    ],
                    'logs' => getBufferedLogs($logger)
                ]);
            }

            // Successful connection
            sendJsonResponse([
                'success' => true,
                'data' => [
                    'sessionId' => $result['sessionId'],
                    'capabilities' => $result['capabilities'],
                    'type' => 'http'
                ],
                'logs' => getBufferedLogs($logger)
            ]);

        } else {
            // Stdio connection (existing behavior)
            if (empty($data['command'])) {
                sendJsonResponse([
                    'success' => false,
                    'error' => 'Command is required'
                ], 400);
            }

            // Security check on command
            if (!validateCommand($data['command'])) {
                $logger->warning('Blocked potentially unsafe command', [
                    'command' => $data['command']
                ]);
                sendJsonResponse([
                    'success' => false,
                    'error' => 'Invalid or unsafe command'
                ], 400);
            }

            // Get optional parameters with defaults
            $args = $data['args'] ?? [];
            $env = $data['env'] ?? null;

            // Validate args is array
            if (!is_array($args)) {
                sendJsonResponse([
                    'success' => false,
                    'error' => 'Arguments must be an array'
                ], 400);
            }

            // Basic argument sanitization
            $args = array_map(function($arg) {
                // Remove any shell operators
                $sanitized = str_replace(['>', '<', '|', '&', ';'], '', $arg);
                return trim($sanitized);
            }, $args);

            // Log connection attempt
            $logger->info('Attempting to connect to MCP server', [
                'command' => $data['command'],
                'args' => $args
            ]);

            // Attempt connection
            $result = $mcpClient->connect($data['command'], $args, $env);

            // Return success response with session info
            sendJsonResponse([
                'success' => true,
                'data' => [
                    'sessionId' => $result['sessionId'],
                    'capabilities' => $result['capabilities'],
                    'type' => 'stdio'
                ],
                'logs' => getBufferedLogs($logger)
            ]);
        }

    } else {
        // Handle session cleanup (DELETE)
        $data = getJsonRequestBody();

        // Validate session ID
        if (empty($data['sessionId'])) {
            sendJsonResponse([
                'success' => false,
                'error' => 'Session ID is required'
            ], 400);
        }

        $sessionId = $data['sessionId'];

        // Verify session exists
        if (!$mcpClient->isSessionValid($sessionId)) {
            sendJsonResponse([
                'success' => false,
                'error' => 'Invalid session ID'
            ], 404);
        }

        // Close the session
        $mcpClient->closeSession($sessionId);

        // Return success response
        sendJsonResponse([
            'success' => true,
            'data' => [
                'message' => 'Session closed successfully'
            ],
            'logs' => getBufferedLogs($logger)
        ]);
    }

} catch (RuntimeException $e) {
    // Handle expected errors
    sendJsonResponse([
        'success' => false,
        'error' => $e->getMessage(),
        'logs' => getBufferedLogs($logger)
    ], 400);

} catch (Throwable $e) {
    // Log unexpected errors and return generic message
    $logger->error('Unexpected error in connect.php', [
        'error' => $e->getMessage(),
        'trace' => $e->getTraceAsString()
    ]);

    sendJsonResponse([
        'success' => false,
        'error' => 'Internal server error occurred',
        'logs' => getBufferedLogs($logger)
    ], 500);
}
