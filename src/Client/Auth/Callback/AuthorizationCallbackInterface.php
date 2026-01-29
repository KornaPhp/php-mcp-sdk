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
 * Filename: Client/Auth/Callback/AuthorizationCallbackInterface.php
 */

declare(strict_types=1);

namespace Mcp\Client\Auth\Callback;

use Mcp\Client\Auth\OAuthException;

/**
 * Interface for handling OAuth authorization callbacks.
 *
 * Implementations handle user interaction during the OAuth authorization flow,
 * presenting the authorization URL to the user and receiving the callback.
 */
interface AuthorizationCallbackInterface
{
    /**
     * Perform the authorization flow.
     *
     * This method should:
     * 1. Present the authorization URL to the user (browser, CLI prompt, etc.)
     * 2. Wait for the user to complete authorization
     * 3. Receive the callback with the authorization code
     * 4. Return the authorization code
     *
     * @param string $authUrl The complete authorization URL
     * @param string $state The state parameter to validate in the callback
     * @return string The authorization code from the callback
     * @throws OAuthException If authorization fails or is cancelled
     */
    public function authorize(string $authUrl, string $state): string;

    /**
     * Get the redirect URI for this callback handler.
     *
     * @return string The redirect URI to use in authorization requests
     */
    public function getRedirectUri(): string;
}
