<?php

/**
 * Model Context Protocol SDK for PHP
 *
 * (c) 2026 Logiscape LLC <https://logiscape.com>
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
 * Filename: tests/Client/Auth/Exception/AuthorizationRedirectExceptionTest.php
 */

declare(strict_types=1);

namespace Mcp\Tests\Client\Auth\Exception;

use Mcp\Client\Auth\Exception\AuthorizationRedirectException;
use Mcp\Client\Auth\OAuthException;
use PHPUnit\Framework\TestCase;

/**
 * Tests for AuthorizationRedirectException class.
 *
 * Validates that the exception carries all required data for web OAuth redirects.
 */
final class AuthorizationRedirectExceptionTest extends TestCase
{
    /**
     * Test that exception extends OAuthException.
     */
    public function testExtendsOAuthException(): void
    {
        $exception = new AuthorizationRedirectException(
            'https://auth.example.com/authorize?response_type=code',
            'state-123',
            'https://app.example.com/callback'
        );

        $this->assertInstanceOf(OAuthException::class, $exception);
    }

    /**
     * Test creating exception with all parameters.
     */
    public function testCreateWithAllParameters(): void
    {
        $authUrl = 'https://auth.example.com/authorize?response_type=code&client_id=test';
        $state = 'unique-state-token';
        $redirectUri = 'https://app.example.com/oauth/callback';
        $message = 'Custom redirect message';

        $exception = new AuthorizationRedirectException(
            $authUrl,
            $state,
            $redirectUri,
            $message
        );

        $this->assertSame($authUrl, $exception->authorizationUrl);
        $this->assertSame($state, $exception->state);
        $this->assertSame($redirectUri, $exception->redirectUri);
        $this->assertSame($message, $exception->getMessage());
    }

    /**
     * Test default message is used when not provided.
     */
    public function testDefaultMessage(): void
    {
        $exception = new AuthorizationRedirectException(
            'https://auth.example.com/authorize',
            'state-123',
            'https://app.example.com/callback'
        );

        $this->assertSame('OAuth authorization requires browser redirect', $exception->getMessage());
    }

    /**
     * Test getAuthorizationUrl method.
     */
    public function testGetAuthorizationUrl(): void
    {
        $authUrl = 'https://auth.example.com/authorize?response_type=code&client_id=test';

        $exception = new AuthorizationRedirectException(
            $authUrl,
            'state',
            'https://app.example.com/callback'
        );

        $this->assertSame($authUrl, $exception->getAuthorizationUrl());
    }

    /**
     * Test getState method.
     */
    public function testGetState(): void
    {
        $state = 'unique-csrf-state-token';

        $exception = new AuthorizationRedirectException(
            'https://auth.example.com/authorize',
            $state,
            'https://app.example.com/callback'
        );

        $this->assertSame($state, $exception->getState());
    }

    /**
     * Test getRedirectUri method.
     */
    public function testGetRedirectUri(): void
    {
        $redirectUri = 'https://app.example.com/oauth/callback';

        $exception = new AuthorizationRedirectException(
            'https://auth.example.com/authorize',
            'state',
            $redirectUri
        );

        $this->assertSame($redirectUri, $exception->getRedirectUri());
    }

    /**
     * Test that readonly properties are accessible.
     */
    public function testReadonlyPropertiesAccessible(): void
    {
        $authUrl = 'https://auth.example.com/authorize';
        $state = 'my-state';
        $redirectUri = 'https://app.example.com/callback';

        $exception = new AuthorizationRedirectException(
            $authUrl,
            $state,
            $redirectUri
        );

        // Access via property
        $this->assertSame($authUrl, $exception->authorizationUrl);
        $this->assertSame($state, $exception->state);
        $this->assertSame($redirectUri, $exception->redirectUri);
    }

    /**
     * Test exception can be caught as OAuthException.
     */
    public function testCatchableAsOAuthException(): void
    {
        try {
            throw new AuthorizationRedirectException(
                'https://auth.example.com/authorize',
                'state-123',
                'https://app.example.com/callback'
            );
        } catch (OAuthException $e) {
            $this->assertInstanceOf(AuthorizationRedirectException::class, $e);
            return;
        }

        $this->fail('Exception was not caught as OAuthException');
    }
}
