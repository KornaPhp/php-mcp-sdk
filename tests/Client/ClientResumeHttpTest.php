<?php

declare(strict_types=1);

namespace Mcp\Tests\Client;

use PHPUnit\Framework\TestCase;
use Mcp\Client\Client;
use Mcp\Client\Transport\HttpSessionManager;
use Mcp\Shared\Version;

/**
 * Tests for Client::resumeHttpSession() and Client::detach().
 *
 * These tests validate the session resume workflow at the Client level,
 * focusing on state management rather than actual HTTP connections.
 */
final class ClientResumeHttpTest extends TestCase
{
    /**
     * Test that HttpSessionManager state round-trips through toArray/fromArray
     * correctly for the resume workflow.
     *
     * This validates the data flow that Client::resumeHttpSession() depends on:
     * connect -> extract state -> detach -> restore state -> resume
     */
    public function testSessionManagerStateRoundTrip(): void
    {
        // Simulate what connectHttp does: create and initialize a session manager
        $original = new HttpSessionManager();
        $original->processResponseHeaders(
            ['mcp-session-id' => 'session-abc-123'],
            200,
            true
        );

        // Simulate what happens after several operations (lastEventId updates)
        $original->updateLastEventId('event-10');

        // Extract state (what webclient stores in $_SESSION)
        $state = $original->toArray();

        // Restore (what resumeHttpSession does)
        $restored = HttpSessionManager::fromArray($state);

        // Verify full fidelity
        $this->assertSame($original->getSessionId(), $restored->getSessionId());
        $this->assertSame($original->getLastEventId(), $restored->getLastEventId());
        $this->assertSame($original->isInitialized(), $restored->isInitialized());
        $this->assertSame($original->isInvalidated(), $restored->isInvalidated());
        $this->assertSame($original->isValid(), $restored->isValid());

        // Verify headers match
        $this->assertSame($original->getRequestHeaders(), $restored->getRequestHeaders());
    }

    /**
     * Test that Client::getTransport() and getSession() return null initially.
     */
    public function testAccessorsReturnNullBeforeConnect(): void
    {
        $client = new Client();

        $this->assertNull($client->getTransport());
        $this->assertNull($client->getSession());
    }

    /**
     * Test that detach() on a client with no connection does not throw.
     */
    public function testDetachWithNoConnectionDoesNotThrow(): void
    {
        $client = new Client();

        // Should not throw
        $client->detach();

        $this->assertNull($client->getTransport());
        $this->assertNull($client->getSession());
    }

    /**
     * Test that resumeHttpSession creates a working session without initialization.
     *
     * The transport's connect() creates streams (no HTTP call yet), so we can
     * verify that the session is created correctly with restored state.
     */
    public function testResumeHttpSessionCreatesRestoredSession(): void
    {
        if (!extension_loaded('curl')) {
            $this->markTestSkipped('cURL extension required');
        }

        $client = new Client();

        $sessionState = [
            'sessionId' => 'test-session',
            'lastEventId' => null,
            'initialized' => true,
            'invalidated' => false,
        ];

        $initResultData = [
            'protocolVersion' => Version::LATEST_PROTOCOL_VERSION,
            'capabilities' => [],
            'serverInfo' => ['name' => 'test', 'version' => '1.0'],
        ];

        // resumeHttpSession should succeed (no HTTP call made during connect)
        $session = $client->resumeHttpSession(
            url: 'http://localhost:9999/',
            sessionManagerState: $sessionState,
            initResultData: $initResultData,
            negotiatedProtocolVersion: Version::LATEST_PROTOCOL_VERSION,
            nextRequestId: 10,
            headers: [],
            httpOptions: ['enableSse' => false]
        );

        // Verify the session is ready for use
        $this->assertNotNull($session);
        $this->assertSame(Version::LATEST_PROTOCOL_VERSION, $session->getNegotiatedProtocolVersion());
        $this->assertSame(10, $session->getNextRequestId());
        $this->assertSame('test', $session->getInitializeResult()->serverInfo->name);

        // Verify transport and session accessors work
        $this->assertNotNull($client->getTransport());
        $this->assertNotNull($client->getSession());

        // Detach — should not throw and should clean up
        $client->detach();
        $this->assertNull($client->getTransport());
        $this->assertNull($client->getSession());
    }

    /**
     * Test that protocol version header is emitted by the transport after resume.
     *
     * After resumeHttpSession(), the transport's session manager must include the
     * MCP-Protocol-Version header in getRequestHeaders(), ensuring it would be
     * sent on all subsequent HTTP requests.
     */
    public function testResumeHttpSessionSetsProtocolVersionHeader(): void
    {
        if (!extension_loaded('curl')) {
            $this->markTestSkipped('cURL extension required');
        }

        $client = new Client();

        $sessionState = [
            'sessionId' => 'session-pv-test',
            'lastEventId' => null,
            'initialized' => true,
            'invalidated' => false,
        ];

        $initResultData = [
            'protocolVersion' => Version::LATEST_PROTOCOL_VERSION,
            'capabilities' => [],
            'serverInfo' => ['name' => 'test', 'version' => '1.0'],
        ];

        $session = $client->resumeHttpSession(
            url: 'http://localhost:9999/',
            sessionManagerState: $sessionState,
            initResultData: $initResultData,
            negotiatedProtocolVersion: Version::LATEST_PROTOCOL_VERSION,
            nextRequestId: 5,
            headers: [],
            httpOptions: ['enableSse' => false]
        );

        // Verify protocol version is set on the session manager
        $transport = $client->getTransport();
        $this->assertNotNull($transport);
        $sessionManager = $transport->getSessionManager();
        $this->assertSame(Version::LATEST_PROTOCOL_VERSION, $sessionManager->getProtocolVersion());

        // Verify the header would be emitted in outgoing requests
        $headers = $sessionManager->getRequestHeaders();
        $this->assertArrayHasKey('MCP-Protocol-Version', $headers);
        $this->assertSame(Version::LATEST_PROTOCOL_VERSION, $headers['MCP-Protocol-Version']);

        $client->detach();
    }
}
