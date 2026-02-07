<?php

declare(strict_types=1);

namespace Mcp\Tests\Client;

use PHPUnit\Framework\TestCase;
use Mcp\Client\ClientSession;
use Mcp\Shared\MemoryStream;
use Mcp\Shared\Version;
use Mcp\Types\InitializeResult;
use Mcp\Types\ServerCapabilities;
use Mcp\Types\Implementation;
use Mcp\Types\JSONRPCResponse;
use Mcp\Types\JsonRpcMessage;
use Mcp\Types\RequestId;

/**
 * Tests for ClientSession::createRestored() — resumed session factory.
 *
 * Validates that restored sessions:
 * - Skip the initialization handshake (no messages sent)
 * - Are immediately ready for operations
 * - Correctly expose state from the original session
 * - Start request IDs at the provided value
 */
final class ClientSessionResumeTest extends TestCase
{
    /**
     * Test that createRestored() skips initialization handshake.
     *
     * A restored session must NOT send 'initialize' or 'notifications/initialized'
     * to the write stream. The server already has an active session; sending
     * initialize again would be a protocol violation.
     */
    public function testCreateRestoredSkipsInitializationHandshake(): void
    {
        $readStream = new MemoryStream();
        $writeStream = new MemoryStream();

        $initResult = $this->createInitResult();

        $session = ClientSession::createRestored(
            readStream: $readStream,
            writeStream: $writeStream,
            initResult: $initResult,
            negotiatedProtocolVersion: Version::LATEST_PROTOCOL_VERSION,
            nextRequestId: 5,
            readTimeout: 2.0
        );

        // Verify no messages were sent to the write stream
        $this->assertNull(
            $writeStream->receive(),
            'Restored session must not send any messages during creation'
        );
    }

    /**
     * Test that restored session returns correct InitializeResult.
     */
    public function testGetInitializeResultReturnsRestoredValue(): void
    {
        $readStream = new MemoryStream();
        $writeStream = new MemoryStream();
        $initResult = $this->createInitResult();

        $session = ClientSession::createRestored(
            readStream: $readStream,
            writeStream: $writeStream,
            initResult: $initResult,
            negotiatedProtocolVersion: Version::LATEST_PROTOCOL_VERSION,
            nextRequestId: 1
        );

        $result = $session->getInitializeResult();
        $this->assertSame($initResult, $result);
        $this->assertSame('test-server', $result->serverInfo->name);
    }

    /**
     * Test that restored session returns correct negotiated protocol version.
     */
    public function testGetNegotiatedProtocolVersionReturnsRestoredValue(): void
    {
        $readStream = new MemoryStream();
        $writeStream = new MemoryStream();

        $session = ClientSession::createRestored(
            readStream: $readStream,
            writeStream: $writeStream,
            initResult: $this->createInitResult(),
            negotiatedProtocolVersion: '2024-11-05',
            nextRequestId: 1
        );

        $this->assertSame('2024-11-05', $session->getNegotiatedProtocolVersion());
    }

    /**
     * Test that request ID counter starts at the provided value.
     *
     * When resuming a session, the request ID must continue from where the
     * previous session left off to avoid collisions with pending responses.
     */
    public function testRequestIdStartsAtProvidedValue(): void
    {
        $readStream = new MemoryStream();
        $writeStream = new MemoryStream();

        $session = ClientSession::createRestored(
            readStream: $readStream,
            writeStream: $writeStream,
            initResult: $this->createInitResult(),
            negotiatedProtocolVersion: Version::LATEST_PROTOCOL_VERSION,
            nextRequestId: 42
        );

        $this->assertSame(42, $session->getNextRequestId());
    }

    /**
     * Test that restored session allows operations (e.g., sendPing).
     *
     * After restoration, the session is in initialized state and should
     * accept operation calls without throwing "not initialized" errors.
     */
    public function testRestoredSessionAllowsOperations(): void
    {
        $readStream = new MemoryStream();
        $writeStream = new MemoryStream();

        // Preload a response for the ping request
        // The restored session will start at request ID 5, so the response
        // must match that ID
        $readStream->send(new JsonRpcMessage(
            new JSONRPCResponse(
                jsonrpc: '2.0',
                id: new RequestId(5),
                result: []
            )
        ));

        $session = ClientSession::createRestored(
            readStream: $readStream,
            writeStream: $writeStream,
            initResult: $this->createInitResult(),
            negotiatedProtocolVersion: Version::LATEST_PROTOCOL_VERSION,
            nextRequestId: 5,
            readTimeout: 2.0
        );

        // This should not throw — session is initialized
        $result = $session->sendPing();
        $this->assertNotNull($result);

        // Verify the ping request was sent to the write stream
        $sentMessage = $writeStream->receive();
        $this->assertInstanceOf(JsonRpcMessage::class, $sentMessage);

        $data = json_decode(json_encode($sentMessage), true);
        $this->assertSame('ping', $data['method']);
        $this->assertSame(5, $data['id']);
    }

    private function createInitResult(): InitializeResult
    {
        return new InitializeResult(
            capabilities: new ServerCapabilities(),
            serverInfo: new Implementation(name: 'test-server', version: '1.0.0'),
            protocolVersion: Version::LATEST_PROTOCOL_VERSION
        );
    }
}
