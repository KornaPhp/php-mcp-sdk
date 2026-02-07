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
 * Provides a web-friendly interface to the MCP client library.
 *
 * For HTTP connections, reuses MCP sessions across PHP requests by persisting
 * session state (Mcp-Session-Id, request ID counter, init result) in $_SESSION.
 * This avoids a full initialization handshake on every operation.
 *
 * For stdio connections, creates fresh connections per operation (PHP limitation:
 * subprocesses cannot persist across HTTP requests).
 *
 * OAuth token management is delegated to the SDK transport when OAuthConfiguration
 * is provided, avoiding duplicate token handling.
 *
 * Supports both local (stdio) and remote (HTTP/HTTPS) MCP servers with optional
 * OAuth 2.0/2.1 authorization.
 */

declare(strict_types=1);

use Monolog\Logger;
use Mcp\Client\Client;
use Mcp\Client\Transport\HttpAuthenticationException;
use Mcp\Client\Transport\StreamableHttpTransport;
use Mcp\Client\Auth\OAuthConfiguration;
use Mcp\Client\Auth\OAuthClient;
use Mcp\Client\Auth\OAuthException;
use Mcp\Client\Auth\Registration\ClientCredentials;

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
     * Build an OAuthConfiguration from the webclient's OAuth config array.
     *
     * Centralizes OAuthConfiguration construction with SessionTokenStorage,
     * WebCallbackHandler, and any configured client credentials.
     *
     * @param array|null $oauthConfig OAuth configuration from the UI
     * @return OAuthConfiguration|null Configuration object, or null if OAuth not configured
     */
    private function buildOAuthConfiguration(?array $oauthConfig): ?OAuthConfiguration {
        if ($oauthConfig === null || empty($oauthConfig['enabled'])) {
            return null;
        }

        $tokenStorage = createTokenStorage();

        $clientCredentials = null;
        if (!empty($oauthConfig['clientId'])) {
            $clientCredentials = new ClientCredentials(
                clientId: $oauthConfig['clientId'],
                clientSecret: $oauthConfig['clientSecret'] ?? null,
                tokenEndpointAuthMethod: $oauthConfig['tokenEndpointAuthMethod']
                    ?? ClientCredentials::AUTH_METHOD_CLIENT_SECRET_POST
            );
        }

        return new OAuthConfiguration(
            clientCredentials: $clientCredentials,
            tokenStorage: $tokenStorage,
            authCallback: new WebCallbackHandler(getCallbackUrl()),
            enableDynamicRegistration: true,
            redirectUri: getCallbackUrl()
        );
    }

    /**
     * Store MCP session state in $_SESSION for later resumption.
     *
     * @param string $sessionId The webclient session ID
     * @param string $url The server URL
     * @param array $httpConfig HTTP configuration
     * @param array|null $oauthConfig OAuth configuration
     */
    private function storeMcpSessionState(string $sessionId, string $url, array $httpConfig, ?array $oauthConfig): void {
        $transport = $this->client->getTransport();
        $session = $this->client->getSession();

        if (!$transport instanceof StreamableHttpTransport || $session === null) {
            return;
        }

        $initResult = $session->getInitializeResult();

        $_SESSION['mcp_servers'][$sessionId]['mcpSessionState'] = $transport->getSessionManager()->toArray();
        $_SESSION['mcp_servers'][$sessionId]['initResultData'] = json_decode(json_encode($initResult->jsonSerialize()), true);
        $_SESSION['mcp_servers'][$sessionId]['protocolVersion'] = $session->getNegotiatedProtocolVersion();
        $_SESSION['mcp_servers'][$sessionId]['nextRequestId'] = $session->getNextRequestId();
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
     * Creates a new connection to an HTTP/HTTPS MCP server.
     *
     * Delegates OAuth token management to the SDK transport via OAuthConfiguration.
     * After successful connection, stores MCP session state for reuse across requests.
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

        // Build HTTP options — let SDK handle OAuth via OAuthConfiguration
        $httpOptions = [
            'connectionTimeout' => $httpConfig['connectionTimeout'] ?? 30.0,
            'readTimeout' => $httpConfig['readTimeout'] ?? 60.0,
            'verifyTls' => $httpConfig['verifyTls'] ?? true,
            'enableSse' => false, // Disable SSE for stateless web requests
        ];

        // Pass OAuth configuration to SDK transport
        $oauthConfigObj = $this->buildOAuthConfiguration($oauthConfig);
        if ($oauthConfigObj !== null) {
            $httpOptions['oauth'] = $oauthConfigObj;
        }

        try {
            // Attempt connection - SDK handles OAuth token injection automatically
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

            // Store MCP session state for reuse
            $this->storeMcpSessionState($sessionId, $url, $httpConfig, $oauthConfig);

            $this->logger->info('HTTP server connection validated', [
                'sessionId' => $sessionId,
                'url' => $url,
                'type' => 'http'
            ]);

            // Detach instead of close — preserve server session
            $this->client->detach();

            return [
                'sessionId' => $sessionId,
                'capabilities' => $initResult->capabilities,
                'type' => 'http'
            ];

        } catch (HttpAuthenticationException $e) {
            // Handle 401 with parsed WWW-Authenticate header
            $this->logger->info('Server requires authentication (401)', ['url' => $url]);

            // If OAuth is enabled, initiate the OAuth flow with WWW-Authenticate data
            if ($oauthConfig !== null && !empty($oauthConfig['enabled'])) {
                return $this->initiateOAuthFlow(
                    $url,
                    $sessionId,
                    $httpConfig,
                    $oauthConfig,
                    $e->getWwwAuthenticate()
                );
            }

            // 401 without OAuth - rethrow with context
            $this->logger->error("HTTP connection failed: " . $e->getMessage());
            throw new RuntimeException("Failed to connect to HTTP MCP server: " . $e->getMessage(), $e->getCode(), $e);

        } catch (RuntimeException $e) {
            // Check if this is a 401 error that we should handle with OAuth (fallback for edge cases)
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
            // Detach on error paths too (may already be detached on success)
            try {
                $this->client->detach();
            } catch (\Exception $closeException) {
                // Log but don't throw - we don't want to mask the original error
                $this->logger->debug('Error detaching client connection', [
                    'error' => $closeException->getMessage()
                ]);
            }
        }
    }

    /**
     * Complete an HTTP connection after OAuth authorization.
     *
     * Delegates OAuth to SDK transport and stores MCP session state for reuse.
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

        // Build HTTP options with OAuth — let SDK handle token injection
        $httpOptions = [
            'connectionTimeout' => $httpConfig['connectionTimeout'] ?? 30.0,
            'readTimeout' => $httpConfig['readTimeout'] ?? 60.0,
            'verifyTls' => $httpConfig['verifyTls'] ?? true,
            'enableSse' => false,
        ];

        $oauthConfigObj = $this->buildOAuthConfiguration($oauthConfig);
        if ($oauthConfigObj !== null) {
            $httpOptions['oauth'] = $oauthConfigObj;
        }

        // Parse custom headers (no manual Authorization injection)
        $headers = [];
        if (!empty($httpConfig['headers'])) {
            $headers = $this->parseHeaders($httpConfig['headers']);
        }

        try {
            // Attempt connection with OAuth handled by SDK
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

            // Store MCP session state for reuse
            $this->storeMcpSessionState($serverId, $url, $httpConfig, $oauthConfig);

            $this->logger->info('HTTP server connection completed after OAuth', [
                'sessionId' => $serverId,
                'url' => $url
            ]);

            // Detach instead of close — preserve server session
            $this->client->detach();

            return [
                'sessionId' => $serverId,
                'capabilities' => $initResult->capabilities,
                'type' => 'http'
            ];

        } catch (\Exception $e) {
            $this->logger->error("HTTP connection failed after OAuth: " . $e->getMessage());
            throw new RuntimeException("Failed to connect after OAuth: " . $e->getMessage(), 0, $e);
        } finally {
            try {
                $this->client->detach();
            } catch (\Exception $closeException) {
                $this->logger->debug('Error detaching client connection', [
                    'error' => $closeException->getMessage()
                ]);
            }
        }
    }

    /**
     * Initiate OAuth flow for an HTTP server using the SDK.
     *
     * @param string $url The server URL
     * @param string $serverId The server identifier
     * @param array $httpConfig HTTP configuration
     * @param array $oauthConfig OAuth configuration
     * @param array $wwwAuth Parsed WWW-Authenticate header (optional)
     * @return array OAuth redirect information
     */
    private function initiateOAuthFlow(
        string $url,
        string $serverId,
        array $httpConfig,
        array $oauthConfig,
        array $wwwAuth = []
    ): array {
        $this->logger->info('Initiating OAuth flow using SDK', ['url' => $url]);

        try {
            $oauthConfigObj = $this->buildOAuthConfiguration($oauthConfig);
            if ($oauthConfigObj === null) {
                throw new RuntimeException('OAuth is not configured');
            }

            $oauthClient = new OAuthClient($oauthConfigObj, $this->logger);

            // Use SDK to initiate authorization - this returns AuthorizationRequest
            $authRequest = $oauthClient->initiateWebAuthorization($url, $wwwAuth);

            // Store AuthorizationRequest in session for oauth_callback.php
            $_SESSION['oauth_pending'][$serverId] = [
                'authRequest' => $authRequest->toArray(),
                'httpConfig' => $httpConfig,
                'oauthConfig' => $oauthConfig,
                'verifyTls' => $httpConfig['verifyTls'] ?? true,
                'startedAt' => time(),
            ];

            $this->logger->info('OAuth flow initiated via SDK', [
                'serverId' => $serverId,
                'authUrl' => $authRequest->authorizationUrl,
            ]);

            // Return information for redirect
            return [
                'requiresOAuth' => true,
                'authUrl' => $authRequest->authorizationUrl,
                'serverId' => $serverId,
                'message' => 'OAuth authorization required. Please authorize in the browser.',
            ];

        } catch (OAuthException $e) {
            $this->logger->error('OAuth initialization failed: ' . $e->getMessage());
            throw new RuntimeException('Failed to initiate OAuth: ' . $e->getMessage(), 0, $e);
        } catch (\Exception $e) {
            $this->logger->error('OAuth flow failed: ' . $e->getMessage());
            throw new RuntimeException('Failed to initiate OAuth flow: ' . $e->getMessage(), 0, $e);
        }
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
            // Create fresh connection (stdio can't persist across PHP requests)
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
     * Execute an MCP operation on an HTTP server.
     *
     * Reuses the MCP session if session state is stored in $_SESSION.
     * Falls back to a full connect if no session state exists or if the
     * server returns 404 (session expired).
     *
     * OAuth is handled by the SDK transport via OAuthConfiguration.
     */
    private function executeOperationHttp(string $sessionId, string $operation, array $params = []): array {
        $serverInfo = $_SESSION['mcp_servers'][$sessionId];
        $url = $serverInfo['url'];
        $httpConfig = $serverInfo['httpConfig'];
        $oauthConfig = $serverInfo['oauthConfig'] ?? null;

        // Verify operation is supported (before any connection attempt)
        $this->validateOperationSupport($operation, $serverInfo['capabilities']);

        // Parse custom headers
        $headers = [];
        if (!empty($httpConfig['headers'])) {
            $headers = $this->parseHeaders($httpConfig['headers']);
        }

        // Build HTTP options — let SDK handle OAuth
        $httpOptions = [
            'connectionTimeout' => $httpConfig['connectionTimeout'] ?? 30.0,
            'readTimeout' => $httpConfig['readTimeout'] ?? 60.0,
            'verifyTls' => $httpConfig['verifyTls'] ?? true,
            'enableSse' => false,
        ];

        $oauthConfigObj = $this->buildOAuthConfiguration($oauthConfig);
        if ($oauthConfigObj !== null) {
            $httpOptions['oauth'] = $oauthConfigObj;
        }

        try {
            // Try to resume existing MCP session
            if (isset($serverInfo['mcpSessionState'])) {
                $this->logger->info('Resuming MCP session', ['sessionId' => $sessionId]);
                $session = $this->client->resumeHttpSession(
                    url: $url,
                    sessionManagerState: $serverInfo['mcpSessionState'],
                    initResultData: $serverInfo['initResultData'],
                    negotiatedProtocolVersion: $serverInfo['protocolVersion'],
                    nextRequestId: $serverInfo['nextRequestId'],
                    headers: $headers,
                    httpOptions: $httpOptions
                );
            } else {
                // No session state — full connect
                $this->logger->info('No MCP session state, performing full connect', ['sessionId' => $sessionId]);
                $session = $this->client->connect($url, $headers, $httpOptions);
                $this->storeMcpSessionState($sessionId, $url, $httpConfig, $oauthConfig);
            }

            // Execute operation
            $result = $this->dispatchOperation($session, $operation, $params);

            // Update request ID counter for next operation
            $_SESSION['mcp_servers'][$sessionId]['nextRequestId'] = $session->getNextRequestId();

            // Store cacheable results
            if (isset($result['store'])) {
                $_SESSION['mcp_servers'][$sessionId][$result['store']] = $result['result'];
            }

            return [
                'result' => $result['result'],
                'logs' => $this->getRecentLogs()
            ];

        } catch (RuntimeException $e) {
            // Handle 404 (session expired on server) — re-initialize
            if ($e->getCode() === 404 && isset($serverInfo['mcpSessionState'])) {
                $this->logger->info('MCP session expired (404), re-initializing', ['sessionId' => $sessionId]);
                return $this->reInitializeAndRetry($sessionId, $operation, $params);
            }
            $this->logger->error("HTTP operation failed: " . $e->getMessage());
            throw new RuntimeException("Failed to execute operation: " . $e->getMessage(), 0, $e);
        } catch (\Exception $e) {
            $this->logger->error("HTTP operation failed: " . $e->getMessage());
            throw new RuntimeException("Failed to execute operation: " . $e->getMessage(), 0, $e);
        } finally {
            // Detach — preserve server session for next operation
            try {
                $this->client->detach();
            } catch (\Exception $closeException) {
                $this->logger->debug('Error detaching client connection', [
                    'error' => $closeException->getMessage()
                ]);
            }
        }
    }

    /**
     * Handle session expiry: perform full connect, update state, retry operation.
     *
     * Called when the server returns 404 indicating the session has expired.
     *
     * @param string $sessionId The webclient session ID
     * @param string $operation The operation to retry
     * @param array $params The operation parameters
     * @return array The operation result
     */
    private function reInitializeAndRetry(string $sessionId, string $operation, array $params): array {
        $serverInfo = $_SESSION['mcp_servers'][$sessionId];
        $url = $serverInfo['url'];
        $httpConfig = $serverInfo['httpConfig'];
        $oauthConfig = $serverInfo['oauthConfig'] ?? null;

        // Parse custom headers
        $headers = [];
        if (!empty($httpConfig['headers'])) {
            $headers = $this->parseHeaders($httpConfig['headers']);
        }

        // Build HTTP options
        $httpOptions = [
            'connectionTimeout' => $httpConfig['connectionTimeout'] ?? 30.0,
            'readTimeout' => $httpConfig['readTimeout'] ?? 60.0,
            'verifyTls' => $httpConfig['verifyTls'] ?? true,
            'enableSse' => false,
        ];

        $oauthConfigObj = $this->buildOAuthConfiguration($oauthConfig);
        if ($oauthConfigObj !== null) {
            $httpOptions['oauth'] = $oauthConfigObj;
        }

        // Need a fresh client since previous one may be in bad state
        $this->client = new Client($this->logger);

        try {
            // Full connect (new initialization handshake)
            $session = $this->client->connect($url, $headers, $httpOptions);

            // Update stored session state
            $initResult = $session->getInitializeResult();
            $capabilitiesArray = json_decode(json_encode($initResult->capabilities), true);

            $_SESSION['mcp_servers'][$sessionId]['capabilities'] = $capabilitiesArray;
            $_SESSION['mcp_servers'][$sessionId]['serverInfo'] = $initResult->serverInfo;
            $_SESSION['mcp_servers'][$sessionId]['created'] = time();
            $this->storeMcpSessionState($sessionId, $url, $httpConfig, $oauthConfig);

            // Execute the operation
            $result = $this->dispatchOperation($session, $operation, $params);

            // Update request ID counter
            $_SESSION['mcp_servers'][$sessionId]['nextRequestId'] = $session->getNextRequestId();

            // Store cacheable results
            if (isset($result['store'])) {
                $_SESSION['mcp_servers'][$sessionId][$result['store']] = $result['result'];
            }

            return [
                'result' => $result['result'],
                'logs' => $this->getRecentLogs()
            ];

        } catch (\Exception $e) {
            $this->logger->error("Re-initialization failed: " . $e->getMessage());
            throw new RuntimeException("Failed to re-initialize session: " . $e->getMessage(), 0, $e);
        } finally {
            try {
                $this->client->detach();
            } catch (\Exception $closeException) {
                $this->logger->debug('Error detaching client connection', [
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
     * Clean up session data.
     *
     * For HTTP sessions with stored MCP session state, resumes the session
     * and sends HTTP DELETE to properly terminate the server-side session.
     */
    public function closeSession(string $sessionId): void {
        if (isset($_SESSION['mcp_servers'][$sessionId])) {
            $serverInfo = $_SESSION['mcp_servers'][$sessionId];

            // For HTTP sessions, properly terminate the server-side session
            if ($serverInfo['type'] === 'http' && isset($serverInfo['mcpSessionState'])) {
                $mcpState = $serverInfo['mcpSessionState'];
                if (!empty($mcpState['sessionId']) && !($mcpState['invalidated'] ?? false)) {
                    try {
                        $url = $serverInfo['url'];
                        $httpConfig = $serverInfo['httpConfig'];
                        $oauthConfig = $serverInfo['oauthConfig'] ?? null;

                        $headers = [];
                        if (!empty($httpConfig['headers'])) {
                            $headers = $this->parseHeaders($httpConfig['headers']);
                        }

                        $httpOptions = [
                            'connectionTimeout' => $httpConfig['connectionTimeout'] ?? 30.0,
                            'readTimeout' => $httpConfig['readTimeout'] ?? 60.0,
                            'verifyTls' => $httpConfig['verifyTls'] ?? true,
                            'enableSse' => false,
                        ];

                        $oauthConfigObj = $this->buildOAuthConfiguration($oauthConfig);
                        if ($oauthConfigObj !== null) {
                            $httpOptions['oauth'] = $oauthConfigObj;
                        }

                        // Resume session and close (sends HTTP DELETE)
                        $this->client->resumeHttpSession(
                            url: $url,
                            sessionManagerState: $mcpState,
                            initResultData: $serverInfo['initResultData'],
                            negotiatedProtocolVersion: $serverInfo['protocolVersion'],
                            nextRequestId: $serverInfo['nextRequestId'],
                            headers: $headers,
                            httpOptions: $httpOptions
                        );
                        $this->client->close(); // This sends HTTP DELETE
                        $this->logger->info('Server-side MCP session terminated', ['sessionId' => $sessionId]);
                    } catch (\Exception $e) {
                        $this->logger->warning('Failed to terminate server session: ' . $e->getMessage());
                    }
                }

                // Clean up OAuth tokens
                if (isset($serverInfo['url'])) {
                    $tokenStorage = createTokenStorage();
                    $tokenStorage->remove($serverInfo['url']);
                }
            } elseif ($serverInfo['type'] === 'http' && isset($serverInfo['url'])) {
                // No MCP session state but still clean up tokens
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
