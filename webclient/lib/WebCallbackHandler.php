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

declare(strict_types=1);

use Mcp\Client\Auth\Callback\AuthorizationCallbackInterface;
use Mcp\Client\Auth\OAuthException;

/**
 * Web-based OAuth callback handler for the webclient.
 *
 * Unlike LoopbackCallbackHandler which creates a local HTTP server,
 * this handler works with browser redirects in a web hosting environment.
 *
 * The authorize() method throws an exception with the authorization URL
 * because the actual authorization happens via browser redirect to the
 * OAuth provider, and the callback is received by oauth_callback.php.
 */
class WebCallbackHandler implements AuthorizationCallbackInterface
{
    private string $callbackUrl;

    /**
     * @param string $callbackUrl The full URL to oauth_callback.php
     */
    public function __construct(string $callbackUrl)
    {
        $this->callbackUrl = $callbackUrl;
    }

    /**
     * {@inheritdoc}
     *
     * In web context, this method cannot complete synchronously because
     * authorization requires a browser redirect. Instead, it throws an
     * OAuthException with the authorization URL for the webclient to
     * redirect the user.
     *
     * @throws OAuthException Always throws with authorization URL
     */
    public function authorize(string $authUrl, string $state): string
    {
        // In web hosting context, we can't wait synchronously for the callback.
        // The webclient must redirect the browser to the authorization URL
        // and handle the callback in oauth_callback.php.
        throw new OAuthException(
            'Web authorization requires browser redirect',
            0,
            null,
            [
                'auth_url' => $authUrl,
                'state' => $state,
                'redirect_uri' => $this->callbackUrl,
                'requires_redirect' => true,
            ]
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getRedirectUri(): string
    {
        return $this->callbackUrl;
    }
}
