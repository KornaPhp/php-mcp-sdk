<?php

/**
 * Model Context Protocol SDK for PHP
 *
 * (c) 2026 Logiscape LLC <https://logiscape.com>
 *
 * Developed by:
 * - Josh Abbott
 * - Claude Opus 4.5 (Anthropic AI model)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @package    logiscape/mcp-sdk-php
 * @author     Josh Abbott <https://joshabbott.com>
 * @copyright  Logiscape LLC
 * @license    MIT License
 * @link       https://github.com/logiscape/mcp-sdk-php
 *
 * Filename: Client/Auth/Discovery/MetadataDiscovery.php
 */

declare(strict_types=1);

namespace Mcp\Client\Auth\Discovery;

use Mcp\Client\Auth\OAuthException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Service for discovering OAuth metadata.
 *
 * Implements RFC9728 for Protected Resource Metadata and
 * RFC8414/OpenID Connect for Authorization Server Metadata.
 */
class MetadataDiscovery
{
    private LoggerInterface $logger;
    private float $timeout;

    /**
     * @param float $timeout HTTP request timeout in seconds
     * @param LoggerInterface|null $logger PSR-3 logger
     */
    public function __construct(
        float $timeout = 30.0,
        ?LoggerInterface $logger = null
    ) {
        $this->timeout = $timeout;
        $this->logger = $logger ?? new NullLogger();
    }

    /**
     * Discover Protected Resource Metadata per RFC9728.
     *
     * @param string $resourceUrl The protected resource URL
     * @param string|null $metadataUrl Optional metadata URL from WWW-Authenticate header
     * @return ProtectedResourceMetadata The discovered metadata
     * @throws OAuthException If discovery fails
     */
    public function discoverResourceMetadata(
        string $resourceUrl,
        ?string $metadataUrl = null
    ): ProtectedResourceMetadata {
        $this->logger->debug("Discovering protected resource metadata for: {$resourceUrl}");

        // Try URLs in order of preference
        $urlsToTry = $this->getResourceMetadataUrls($resourceUrl, $metadataUrl);

        $lastError = null;
        foreach ($urlsToTry as $url) {
            try {
                $this->logger->debug("Trying resource metadata URL: {$url}");
                $data = $this->fetchJson($url);

                if ($this->isValidResourceMetadata($data)) {
                    $this->logger->info("Found protected resource metadata at: {$url}");
                    return ProtectedResourceMetadata::fromArray($data);
                }
            } catch (\Exception $e) {
                $this->logger->debug("Failed to fetch from {$url}: {$e->getMessage()}");
                $lastError = $e;
            }
        }

        throw OAuthException::discoveryFailed(
            $resourceUrl,
            $lastError?->getMessage() ?? 'No valid metadata found at any location'
        );
    }

    /**
     * Discover Authorization Server Metadata per RFC8414 and OpenID Connect.
     *
     * @param string $issuerUrl The authorization server issuer URL
     * @return AuthorizationServerMetadata The discovered metadata
     * @throws OAuthException If discovery fails or PKCE is not supported
     */
    public function discoverAuthorizationServerMetadata(
        string $issuerUrl
    ): AuthorizationServerMetadata {
        $this->logger->debug("Discovering authorization server metadata for: {$issuerUrl}");

        $urlsToTry = $this->getAuthServerMetadataUrls($issuerUrl);

        $lastError = null;
        foreach ($urlsToTry as $url) {
            try {
                $this->logger->debug("Trying AS metadata URL: {$url}");
                $data = $this->fetchJson($url);

                if ($this->isValidAuthServerMetadata($data)) {
                    $metadata = AuthorizationServerMetadata::fromArray($data);

                    // MCP MUST verify PKCE support
                    if (!$metadata->supportsPkce()) {
                        throw OAuthException::pkceNotSupported();
                    }

                    $this->logger->info("Found authorization server metadata at: {$url}");
                    return $metadata;
                }
            } catch (OAuthException $e) {
                // Re-throw OAuth exceptions (like PKCE not supported)
                throw $e;
            } catch (\Exception $e) {
                $this->logger->debug("Failed to fetch from {$url}: {$e->getMessage()}");
                $lastError = $e;
            }
        }

        throw OAuthException::discoveryFailed(
            $issuerUrl,
            $lastError?->getMessage() ?? 'No valid metadata found at any location'
        );
    }

    /**
     * Get the list of URLs to try for Protected Resource Metadata.
     *
     * @param string $resourceUrl The protected resource URL
     * @param string|null $metadataUrl Optional metadata URL from header
     * @return array List of URLs to try
     */
    private function getResourceMetadataUrls(string $resourceUrl, ?string $metadataUrl): array
    {
        $urls = [];

        // Priority 1: Explicit metadata URL from WWW-Authenticate header
        if ($metadataUrl !== null) {
            $urls[] = $metadataUrl;
        }

        $parsed = parse_url($resourceUrl);
        $scheme = $parsed['scheme'] ?? 'https';
        $host = $parsed['host'] ?? '';
        $port = isset($parsed['port']) ? ":{$parsed['port']}" : '';
        $path = $parsed['path'] ?? '';

        $origin = "{$scheme}://{$host}{$port}";

        // Priority 2: Path-aware well-known location
        // /.well-known/oauth-protected-resource/{path}
        if ($path !== '' && $path !== '/') {
            $pathWithoutLeadingSlash = ltrim($path, '/');
            $urls[] = "{$origin}/.well-known/oauth-protected-resource/{$pathWithoutLeadingSlash}";
        }

        // Priority 3: Root well-known location
        // /.well-known/oauth-protected-resource
        $urls[] = "{$origin}/.well-known/oauth-protected-resource";

        return $urls;
    }

    /**
     * Get the list of URLs to try for Authorization Server Metadata.
     *
     * @param string $issuerUrl The authorization server issuer URL
     * @return array List of URLs to try
     */
    private function getAuthServerMetadataUrls(string $issuerUrl): array
    {
        $urls = [];

        $parsed = parse_url($issuerUrl);
        $scheme = $parsed['scheme'] ?? 'https';
        $host = $parsed['host'] ?? '';
        $port = isset($parsed['port']) ? ":{$parsed['port']}" : '';
        $path = $parsed['path'] ?? '';

        $origin = "{$scheme}://{$host}{$port}";

        // Check if there's a path component
        $hasPath = $path !== '' && $path !== '/';

        if ($hasPath) {
            $pathWithoutLeadingSlash = ltrim($path, '/');

            // RFC8414 path-aware: /.well-known/oauth-authorization-server/{path}
            $urls[] = "{$origin}/.well-known/oauth-authorization-server/{$pathWithoutLeadingSlash}";

            // OIDC path-aware: /.well-known/openid-configuration/{path}
            $urls[] = "{$origin}/.well-known/openid-configuration/{$pathWithoutLeadingSlash}";

            // OIDC suffix: {path}/.well-known/openid-configuration
            $urls[] = "{$origin}/{$pathWithoutLeadingSlash}/.well-known/openid-configuration";
        } else {
            // RFC8414: /.well-known/oauth-authorization-server
            $urls[] = "{$origin}/.well-known/oauth-authorization-server";

            // OIDC: /.well-known/openid-configuration
            $urls[] = "{$origin}/.well-known/openid-configuration";
        }

        return $urls;
    }

    /**
     * Fetch JSON from a URL.
     *
     * @param string $url The URL to fetch
     * @return array The decoded JSON
     * @throws \RuntimeException If fetch fails
     */
    private function fetchJson(string $url): array
    {
        $ch = curl_init($url);
        if ($ch === false) {
            throw new \RuntimeException('Failed to initialize cURL');
        }

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => (int) $this->timeout,
            CURLOPT_HTTPHEADER => [
                'Accept: application/json',
            ],
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($response === false) {
            throw new \RuntimeException("HTTP request failed: {$error}");
        }

        if ($httpCode !== 200) {
            throw new \RuntimeException("HTTP {$httpCode} response");
        }

        $data = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \RuntimeException('Invalid JSON response: ' . json_last_error_msg());
        }

        return $data;
    }

    /**
     * Validate that data looks like valid Protected Resource Metadata.
     *
     * @param array $data The metadata to validate
     * @return bool True if valid
     */
    private function isValidResourceMetadata(array $data): bool
    {
        // Must have 'resource' field
        if (!isset($data['resource'])) {
            return false;
        }

        // Should have authorization_servers (empty array is technically valid)
        if (isset($data['authorization_servers']) && !is_array($data['authorization_servers'])) {
            return false;
        }

        return true;
    }

    /**
     * Validate that data looks like valid Authorization Server Metadata.
     *
     * @param array $data The metadata to validate
     * @return bool True if valid
     */
    private function isValidAuthServerMetadata(array $data): bool
    {
        // Must have issuer, authorization_endpoint, and token_endpoint
        return isset($data['issuer'])
            && isset($data['authorization_endpoint'])
            && isset($data['token_endpoint']);
    }

    /**
     * Parse the WWW-Authenticate header to extract resource_metadata URL.
     *
     * @param string $header The WWW-Authenticate header value
     * @return array Parsed header with 'resource_metadata' if present
     */
    public static function parseWwwAuthenticate(string $header): array
    {
        $result = [
            'scheme' => null,
            'realm' => null,
            'resource_metadata' => null,
            'scope' => null,
            'error' => null,
            'error_description' => null,
        ];

        // Extract scheme (Bearer, etc.)
        if (preg_match('/^(\w+)\s+/', $header, $matches)) {
            $result['scheme'] = $matches[1];
            $header = substr($header, strlen($matches[0]));
        }

        // Parse key="value" pairs
        $pattern = '/(\w+)=(?:"([^"]*)"|([\w.-]+))/';
        if (preg_match_all($pattern, $header, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                $key = $match[1];
                $value = $match[2] !== '' ? $match[2] : ($match[3] ?? '');
                $result[$key] = $value;
            }
        }

        return $result;
    }
}
