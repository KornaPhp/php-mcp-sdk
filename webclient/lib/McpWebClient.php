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
 * MCP Web Client Wrapper
 *
 * Provides a web-friendly interface to the MCP client library by creating fresh
 * connections for each operation while maintaining server information and capabilities
 * in PHP sessions.
 *
 * Supports both local (stdio) and remote (HTTP/HTTPS) MCP servers with optional
 * OAuth 2.0/2.1 authorization.
 */

declare(strict_types=1);

use Monolog\Logger;
use Mcp\Client\Client;
use Mcp\Client\Transport\StdioServerParameters;
use Mcp\Client\Auth\OAuthConfiguration;
use Mcp\Client\Auth\OAuthClient;
use Mcp\Client\Auth\OAuthException;
use Mcp\Client\Auth\Discovery\MetadataDiscovery;
use Mcp\Client\Auth\Pkce\PkceGenerator;
use Mcp\Client\Auth\Registration\ClientCredentials;
use Mcp\Types\InitializeResult;

class McpWebClient {
    /** @var Client */
    private Client $client;

    /** @var Logger */
    private Logger $logger;

    public function __construct(Logger $logger) {
        $this->client = new Client($logger);
        $this->logger = $logger;

        // Initialize session storage if not exists
        if (!isset($_SESSION['mcp_servers'])) {
            $_SESSION['mcp_servers'] = [];
        }
        if (!isset($_SESSION['oauth_pending'])) {
            $_SESSION['oauth_pending'] = [];
        }
        if (!isset($_SESSION['oauth_completed'])) {
            $_SESSION['oauth_completed'] = [];
        }
    }

    /**
     * Creates a new connection to test a stdio server and stores its capabilities
     */
    public function connect(string $command, array $args = [], ?array $env = null): array {
        $sessionId = $this->generateSessionId($command, $args);

        try {
            // Create new connection to test server
            $session = $this->client->connect($command, $args, $env);

            // Get server capabilities
            $initResult = $session->getInitializeResult();

            // Convert capabilities to a plain array so it serializes cleanly
            $capabilitiesArray = json_decode(json_encode($initResult->capabilities), true);

            // Store server info in PHP session
            $_SESSION['mcp_servers'][$sessionId] = [
                'type' => 'stdio',
                'command' => $command,
                'args' => $args,
                'env' => $env,
                'created' => time(),
                'capabilities' => $capabilitiesArray,
                'serverInfo' => $initResult->serverInfo
            ];

            $this->logger->info('Server connection validated', [
                'sessionId' => $sessionId,
                'command' => $command,
                'type' => 'stdio'
            ]);

            // Cleanup test connection
            $this->client->close();

            return [
                'sessionId' => $sessionId,
                'capabilities' => $initResult->capabilities
            ];
        } catch (\Exception $e) {
            $this->logger->error("Connection failed: " . $e->getMessage());
            throw new RuntimeException("Failed to connect to MCP server: " . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Creates a new connection to an HTTP/HTTPS MCP server
     *
     * @param string $url The HTTP(S) URL of the MCP server
     * @param array $httpConfig HTTP configuration options
     * @param array|null $oauthConfig OAuth configuration (optional)
     * @return array Connection result with sessionId and capabilities, or OAuth redirect info
     */
    public function connectHttp(string $url, array $httpConfig = [], ?array $oauthConfig = null): array {
        $sessionId = $this->generateHttpSessionId($url);

        // Parse custom headers
        $headers = [];
        if (!empty($httpConfig['headers'])) {
            $headers = $this->parseHeaders($httpConfig['headers']);
        }

        // Check if we have completed OAuth tokens for this server
        $tokenStorage = createTokenStorage();
        $existingTokens = $tokenStorage->retrieve($url);

        if ($existingTokens !== null && !$existingTokens->isExpired()) {
            // We have valid tokens, add them to headers
            $headers['Authorization'] = $existingTokens->getAuthorizationHeader();
            $this->logger->info('Using existing OAuth tokens', ['url' => $url]);
        }

        // Build HTTP options for the client
        $httpOptions = [
            'connectionTimeout' => $httpConfig['connectionTimeout'] ?? 30.0,
            'readTimeout' => $httpConfig['readTimeout'] ?? 60.0,
            'verifyTls' => $httpConfig['verifyTls'] ?? true,
            'enableSse' => false, // Disable SSE for stateless web requests
        ];

        try {
            // Attempt connection - SDK will throw on HTTP errors (401, 403, etc.)
            $session = $this->client->connect($url, $headers, $httpOptions);

            // Get server capabilities
            $initResult = $session->getInitializeResult();

            // Convert capabilities to a plain array so it serializes cleanly
            $capabilitiesArray = json_decode(json_encode($initResult->capabilities), true);

            // Store server info in PHP session
            $_SESSION['mcp_servers'][$sessionId] = [
                'type' => 'http',
                'url' => $url,
                'httpConfig' => $httpConfig,
                'oauthConfig' => $oauthConfig,
                'created' => time(),
                'capabilities' => $capabilitiesArray,
                'serverInfo' => $initResult->serverInfo
            ];

            $this->logger->info('HTTP server connection validated', [
                'sessionId' => $sessionId,
                'url' => $url,
                'type' => 'http'
            ]);

            return [
                'sessionId' => $sessionId,
                'capabilities' => $initResult->capabilities,
                'type' => 'http'
            ];

        } catch (RuntimeException $e) {
            // Check if this is a 401 error that we should handle with OAuth
            $code = $e->getCode();
            $message = $e->getMessage();

            if ($code === 401 || strpos($message, '401') !== false) {
                $this->logger->info('Server requires authentication (401)', ['url' => $url]);

                // If OAuth is enabled, initiate the OAuth flow
                if ($oauthConfig !== null && !empty($oauthConfig['enabled'])) {
                    return $this->initiateOAuthFlow($url, $sessionId, $httpConfig, $oauthConfig);
                }
            }

            // For all other errors (or 401 without OAuth), rethrow with context
            $this->logger->error("HTTP connection failed: " . $e->getMessage());
            throw new RuntimeException("Failed to connect to HTTP MCP server: " . $e->getMessage(), $code, $e);

        } catch (\Exception $e) {
            $this->logger->error("HTTP connection failed: " . $e->getMessage());
            throw new RuntimeException("Failed to connect to HTTP MCP server: " . $e->getMessage(), 0, $e);
        } finally {
            // Always cleanup the client connection
            try {
                $this->client->close();
            } catch (\Exception $closeException) {
                // Log but don't throw - we don't want to mask the original error
                $this->logger->debug('Error closing client connection', [
                    'error' => $closeException->getMessage()
                ]);
            }
        }
    }

    /**
     * Complete an HTTP connection after OAuth authorization
     *
     * @param string $serverId The server ID from the OAuth callback
     * @return array Connection result with sessionId and capabilities
     */
    public function completeOAuthConnection(string $serverId): array {
        if (!isset($_SESSION['oauth_completed'][$serverId])) {
            throw new RuntimeException('No completed OAuth flow found for this server');
        }

        $completed = $_SESSION['oauth_completed'][$serverId];
        $url = $completed['resourceUrl'];
        $httpConfig = $completed['httpConfig'];
        $oauthConfig = $completed['oauthConfig'];

        // Clean up completed OAuth data
        unset($_SESSION['oauth_completed'][$serverId]);

        // Get tokens
        $tokenStorage = createTokenStorage();
        $tokens = $tokenStorage->retrieve($url);

        if ($tokens === null || $tokens->isExpired()) {
            throw new RuntimeException('OAuth tokens are missing or expired');
        }

        // Build HTTP options
        $httpOptions = [
            'connectionTimeout' => $httpConfig['connectionTimeout'] ?? 30.0,
            'readTimeout' => $httpConfig['readTimeout'] ?? 60.0,
            'verifyTls' => $httpConfig['verifyTls'] ?? true,
            'enableSse' => false,
        ];

        // Parse custom headers and add authorization
        $headers = [];
        if (!empty($httpConfig['headers'])) {
            $headers = $this->parseHeaders($httpConfig['headers']);
        }
        $headers['Authorization'] = $tokens->getAuthorizationHeader();

        try {
            // Attempt connection with tokens
            $session = $this->client->connect($url, $headers, $httpOptions);

            // Get server capabilities
            $initResult = $session->getInitializeResult();

            // Convert capabilities to a plain array
            $capabilitiesArray = json_decode(json_encode($initResult->capabilities), true);

            // Store server info in PHP session
            $_SESSION['mcp_servers'][$serverId] = [
                'type' => 'http',
                'url' => $url,
                'httpConfig' => $httpConfig,
                'oauthConfig' => $oauthConfig,
                'created' => time(),
                'capabilities' => $capabilitiesArray,
                'serverInfo' => $initResult->serverInfo
            ];

            $this->logger->info('HTTP server connection completed after OAuth', [
                'sessionId' => $serverId,
                'url' => $url
            ]);

            return [
                'sessionId' => $serverId,
                'capabilities' => $initResult->capabilities,
                'type' => 'http'
            ];

        } catch (\Exception $e) {
            $this->logger->error("HTTP connection failed after OAuth: " . $e->getMessage());
            throw new RuntimeException("Failed to connect after OAuth: " . $e->getMessage(), 0, $e);
        } finally {
            // Always cleanup the client connection
            try {
                $this->client->close();
            } catch (\Exception $closeException) {
                $this->logger->debug('Error closing client connection', [
                    'error' => $closeException->getMessage()
                ]);
            }
        }
    }

    /**
     * Initiate OAuth flow for an HTTP server
     */
    private function initiateOAuthFlow(string $url, string $serverId, array $httpConfig, array $oauthConfig): array {
        $this->logger->info('Initiating OAuth flow', ['url' => $url]);

        // Discover metadata
        $discovery = new MetadataDiscovery(30.0, $this->logger);

        // First try to discover resource metadata
        try {
            $resourceMetadata = $discovery->discoverResourceMetadata($url);
            $authServerUrl = $resourceMetadata->getPrimaryAuthorizationServer();

            if ($authServerUrl === null) {
                throw new RuntimeException('No authorization server found in resource metadata');
            }

            $authServerMetadata = $discovery->discoverAuthorizationServerMetadata($authServerUrl);

        } catch (\Exception $e) {
            $this->logger->error('Metadata discovery failed: ' . $e->getMessage());
            throw new RuntimeException('Failed to discover OAuth metadata: ' . $e->getMessage(), 0, $e);
        }

        // Generate PKCE
        $pkce = new PkceGenerator();
        $pkceData = $pkce->generate();

        // Generate state for CSRF protection
        $state = bin2hex(random_bytes(16));

        // Get redirect URI
        $redirectUri = getCallbackUrl();

        // Determine client ID
        $clientId = $oauthConfig['clientId'] ?? null;
        $clientSecret = $oauthConfig['clientSecret'] ?? null;

        // If no client ID, try dynamic client registration
        if (empty($clientId) && $authServerMetadata->supportsDynamicRegistration()) {
            $this->logger->info('Attempting dynamic client registration');

            try {
                $dcr = new \Mcp\Client\Auth\Registration\DynamicClientRegistration(30.0, $this->logger);
                $metadata = \Mcp\Client\Auth\Registration\DynamicClientRegistration::buildMetadata(
                    'MCP Web Client',
                    [$redirectUri]
                );
                $credentials = $dcr->register($authServerMetadata, $metadata);
                $clientId = $credentials->clientId;
                $clientSecret = $credentials->clientSecret;
            } catch (\Exception $e) {
                $this->logger->warning('Dynamic client registration failed: ' . $e->getMessage());
                throw new RuntimeException('No client ID provided and dynamic registration failed', 0, $e);
            }
        }

        if (empty($clientId)) {
            throw new RuntimeException('Client ID is required for OAuth authorization');
        }

        // Determine scopes
        $scopes = [];
        if (isset($resourceMetadata->scopesSupported)) {
            $scopes = $resourceMetadata->scopesSupported;
        }

        // Build authorization URL
        $authParams = [
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri,
            'state' => $state,
            'code_challenge' => $pkceData['challenge'],
            'code_challenge_method' => $pkceData['method'],
            'resource' => $resourceMetadata->resource ?? $url,
        ];

        if (!empty($scopes)) {
            $authParams['scope'] = implode(' ', $scopes);
        }

        $authUrl = $authServerMetadata->authorizationEndpoint . '?' . http_build_query($authParams);

        // Store pending OAuth flow in session
        $_SESSION['oauth_pending'][$serverId] = [
            'state' => $state,
            'verifier' => $pkceData['verifier'],
            'resourceUrl' => $url,
            'resource' => $resourceMetadata->resource ?? $url,
            'tokenEndpoint' => $authServerMetadata->tokenEndpoint,
            'issuer' => $authServerMetadata->issuer,
            'clientId' => $clientId,
            'clientSecret' => $clientSecret,
            'httpConfig' => $httpConfig,
            'oauthConfig' => $oauthConfig,
            'verifyTls' => $httpConfig['verifyTls'] ?? true,
            'startedAt' => time(),
        ];

        $this->logger->info('OAuth flow initiated', [
            'serverId' => $serverId,
            'authEndpoint' => $authServerMetadata->authorizationEndpoint,
        ]);

        // Return information for redirect
        return [
            'requiresOAuth' => true,
            'authUrl' => $authUrl,
            'serverId' => $serverId,
            'message' => 'OAuth authorization required. Please authorize in the browser.',
        ];
    }

    /**
     * Execute an MCP operation with a fresh connection
     */
    public function executeOperation(string $sessionId, string $operation, array $params = []): array {
        if (!isset($_SESSION['mcp_servers'][$sessionId])) {
            throw new RuntimeException('Invalid or expired session');
        }

        $serverInfo = $_SESSION['mcp_servers'][$sessionId];
        $type = $serverInfo['type'] ?? 'stdio';

        if ($type === 'http') {
            return $this->executeOperationHttp($sessionId, $operation, $params);
        }

        return $this->executeOperationStdio($sessionId, $operation, $params);
    }

    /**
     * Execute an MCP operation on a stdio server
     */
    private function executeOperationStdio(string $sessionId, string $operation, array $params = []): array {
        $serverInfo = $_SESSION['mcp_servers'][$sessionId];

        // Verify operation is supported (before any connection attempt)
        $this->validateOperationSupport($operation, $serverInfo['capabilities']);

        try {
            // Create fresh connection
            $session = $this->client->connect(
                $serverInfo['command'],
                $serverInfo['args'],
                $serverInfo['env'] ?? null
            );

            // Execute operation
            $result = $this->dispatchOperation($session, $operation, $params);

            // Store cacheable results
            if (isset($result['store'])) {
                $_SESSION['mcp_servers'][$sessionId][$result['store']] = $result['result'];
            }

            return [
                'result' => $result['result'],
                'logs' => $this->getRecentLogs()
            ];

        } catch (\Exception $e) {
            $this->logger->error("Operation failed: " . $e->getMessage());
            throw new RuntimeException("Failed to execute operation: " . $e->getMessage(), 0, $e);
        } finally {
            // Always cleanup connection
            try {
                $this->client->close();
            } catch (\Exception $closeException) {
                $this->logger->debug('Error closing client connection', [
                    'error' => $closeException->getMessage()
                ]);
            }
        }
    }

    /**
     * Execute an MCP operation on an HTTP server
     */
    private function executeOperationHttp(string $sessionId, string $operation, array $params = []): array {
        $serverInfo = $_SESSION['mcp_servers'][$sessionId];
        $url = $serverInfo['url'];
        $httpConfig = $serverInfo['httpConfig'];

        // Verify operation is supported (before any connection attempt)
        $this->validateOperationSupport($operation, $serverInfo['capabilities']);

        // Build HTTP options
        $httpOptions = [
            'connectionTimeout' => $httpConfig['connectionTimeout'] ?? 30.0,
            'readTimeout' => $httpConfig['readTimeout'] ?? 60.0,
            'verifyTls' => $httpConfig['verifyTls'] ?? true,
            'enableSse' => false,
        ];

        // Parse custom headers
        $headers = [];
        if (!empty($httpConfig['headers'])) {
            $headers = $this->parseHeaders($httpConfig['headers']);
        }

        // Add OAuth tokens if available
        $tokenStorage = createTokenStorage();
        $tokens = $tokenStorage->retrieve($url);
        if ($tokens !== null && !$tokens->isExpired()) {
            $headers['Authorization'] = $tokens->getAuthorizationHeader();
        }

        try {
            // Create fresh connection
            $session = $this->client->connect($url, $headers, $httpOptions);

            // Execute operation
            $result = $this->dispatchOperation($session, $operation, $params);

            // Store cacheable results
            if (isset($result['store'])) {
                $_SESSION['mcp_servers'][$sessionId][$result['store']] = $result['result'];
            }

            return [
                'result' => $result['result'],
                'logs' => $this->getRecentLogs()
            ];

        } catch (\Exception $e) {
            $this->logger->error("HTTP operation failed: " . $e->getMessage());
            throw new RuntimeException("Failed to execute operation: " . $e->getMessage(), 0, $e);
        } finally {
            // Always cleanup connection
            try {
                $this->client->close();
            } catch (\Exception $closeException) {
                $this->logger->debug('Error closing client connection', [
                    'error' => $closeException->getMessage()
                ]);
            }
        }
    }

    /**
     * Dispatch an operation to the session
     */
    private function dispatchOperation($session, string $operation, array $params): array {
        return match($operation) {
            'list_prompts' => [
                'result' => $session->listPrompts(),
                'store' => 'prompts'
            ],
            'get_prompt' => [
                'result' => $session->getPrompt($params['name'], $params['arguments'] ?? null)
            ],
            'list_tools' => [
                'result' => $session->listTools(),
                'store' => 'tools'
            ],
            'call_tool' => [
                'result' => $session->callTool($params['name'], $params['arguments'] ?? null)
            ],
            'list_resources' => [
                'result' => $session->listResources(),
                'store' => 'resources'
            ],
            'read_resource' => [
                'result' => $session->readResource($params['uri'])
            ],
            'ping' => [
                'result' => $session->sendPing()
            ],
            default => throw new InvalidArgumentException("Unknown operation: $operation")
        };
    }

    /**
     * Clean up session data
     */
    public function closeSession(string $sessionId): void {
        // Clean up any associated tokens
        if (isset($_SESSION['mcp_servers'][$sessionId])) {
            $serverInfo = $_SESSION['mcp_servers'][$sessionId];
            if ($serverInfo['type'] === 'http' && isset($serverInfo['url'])) {
                $tokenStorage = createTokenStorage();
                $tokenStorage->remove($serverInfo['url']);
            }
        }

        unset($_SESSION['mcp_servers'][$sessionId]);
        unset($_SESSION['oauth_pending'][$sessionId]);
        unset($_SESSION['oauth_completed'][$sessionId]);

        $this->logger->info('Session closed', ['sessionId' => $sessionId]);
    }

    /**
     * Check if session is valid
     */
    public function isSessionValid(string $sessionId): bool {
        return isset($_SESSION['mcp_servers'][$sessionId]);
    }

    /**
     * Get server capabilities
     */
    public function getCapabilities(string $sessionId): ?array {
        return $_SESSION['mcp_servers'][$sessionId]['capabilities'] ?? null;
    }

    /**
     * Get session type (stdio or http)
     */
    public function getSessionType(string $sessionId): ?string {
        return $_SESSION['mcp_servers'][$sessionId]['type'] ?? null;
    }

    /**
     * Get recent log entries
     */
    private function getRecentLogs(): array {
        if ($this->logger instanceof BufferLogger) {
            return $this->logger->getBuffer();
        }
        return [];
    }

    /**
     * Generate a unique session ID based on server config (stdio)
     */
    private function generateSessionId(string $command, array $args): string {
        $data = json_encode(['stdio', $command, $args]);
        return hash('sha256', $data);
    }

    /**
     * Generate a unique session ID for HTTP servers
     */
    private function generateHttpSessionId(string $url): string {
        $data = json_encode(['http', $url]);
        return hash('sha256', $data);
    }

    /**
     * Parse headers from textarea format (key: value per line)
     */
    private function parseHeaders(string $headersText): array {
        $headers = [];
        $lines = explode("\n", $headersText);
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line)) {
                continue;
            }
            $colonPos = strpos($line, ':');
            if ($colonPos !== false) {
                $key = trim(substr($line, 0, $colonPos));
                $value = trim(substr($line, $colonPos + 1));
                if (!empty($key)) {
                    $headers[$key] = $value;
                }
            }
        }
        return $headers;
    }

    /**
     * Validate operation against server capabilities
     */
    private function validateOperationSupport(string $operation, array $capabilities): void {
        $operationMap = [
            'list_prompts' => 'prompts',
            'get_prompt' => 'prompts',
            'list_tools' => 'tools',
            'call_tool' => 'tools',
            'list_resources' => 'resources',
            'read_resource' => 'resources'
        ];

        if (isset($operationMap[$operation])) {
            $requiredCapability = $operationMap[$operation];
            if (!isset($capabilities[$requiredCapability])) {
                throw new RuntimeException("Server does not support $requiredCapability operations");
            }
        }
    }
}
