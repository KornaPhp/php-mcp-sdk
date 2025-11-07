<?php

/**
 * Model Context Protocol SDK for PHP
 *
 * (c) 2025 Logiscape LLC <https://logiscape.com>
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

namespace Mcp\Tests\Client;

use PHPUnit\Framework\TestCase;
use Mcp\Client\ClientSession;
use Mcp\Shared\MemoryStream;
use Mcp\Shared\Version;
use Mcp\Types\JSONRPCResponse;
use Mcp\Types\JSONRPCRequest;
use Mcp\Types\JSONRPCNotification;
use Mcp\Types\JsonRpcMessage;
use Mcp\Types\InitializeResult;
use Mcp\Types\ServerCapabilities;
use Mcp\Types\Implementation;
use Mcp\Types\RequestId;

/**
 * Tests for ClientSession initialization handshake.
 *
 * Validates that the client correctly:
 * - Sends an 'initialize' request
 * - Receives and validates the InitializeResult
 * - Sends the 'notifications/initialized' notification
 * - Properly sets negotiated protocol version
 * - Correctly reports feature support based on protocol version
 */
class ClientSessionInitializeTest extends TestCase
{
    /**
     * Test that initialize() sends the correct message sequence.
     *
     * Wire protocol verification:
     * 1. Client sends 'initialize' JSON-RPC request
     * 2. Server responds with InitializeResult
     * 3. Client sends 'notifications/initialized' notification
     *
     * This test preloads a valid InitializeResult into the read stream,
     * calls initialize(), and verifies the exact messages written to
     * the write stream match the expected protocol sequence.
     */
    public function testInitializeHandshakeSendsCorrectSequence(): void
    {
        // Arrange: Create two MemoryStream queues for bidirectional communication
        $readStream = new MemoryStream();   // Client reads server responses from this
        $writeStream = new MemoryStream();  // Client writes requests/notifications to this

        // Preload the read stream with a mock server response
        // The server responds with InitializeResult for protocol version 2025-03-26
        // Note: The result must be in array format (as it would be from JSON decoding)
        // not as a pre-constructed object, because BaseSession::sendRequest will call
        // InitializeResult::fromResponseData() on it
        $initializeResultData = [
            'protocolVersion' => Version::LATEST_PROTOCOL_VERSION,
            'capabilities' => [],
            'serverInfo' => [
                'name' => 'test-server',
                'version' => '1.0.0'
            ]
        ];

        // Create a JSON-RPC response with request ID 1 (clients typically start at 1)
        $readStream->send($this->createResponse($initializeResultData));

        // Create the client session with a small read timeout to prevent hanging in tests
        $session = new ClientSession($readStream, $writeStream, readTimeout: 2.0);

        // Act: Initialize the session (this should trigger the handshake)
        $session->initialize();

        // Assert: Verify the first message written is the 'initialize' request
        $firstMessage = $writeStream->receive();
        $this->assertInstanceOf(JsonRpcMessage::class, $firstMessage, 'First message should be a JsonRpcMessage');
        $this->assertInstanceOf(JSONRPCRequest::class, $firstMessage->message, 'First message should be a JSON-RPC request');

        // Decode the request to inspect its contents
        $firstMessageData = json_decode(json_encode($firstMessage), true);
        $this->assertEquals('2.0', $firstMessageData['jsonrpc'], 'JSON-RPC version must be 2.0');
        $this->assertEquals('initialize', $firstMessageData['method'], 'First request method must be "initialize"');
        $this->assertArrayHasKey('id', $firstMessageData, 'Initialize request must have an ID');
        $this->assertArrayHasKey('params', $firstMessageData, 'Initialize request must have params');

        // Verify params contain required fields
        $params = $firstMessageData['params'];
        $this->assertArrayHasKey('protocolVersion', $params, 'Params must include protocolVersion');
        $this->assertEquals(Version::LATEST_PROTOCOL_VERSION, $params['protocolVersion'], 'Should request latest protocol version');
        $this->assertArrayHasKey('capabilities', $params, 'Params must include capabilities');
        $this->assertArrayHasKey('clientInfo', $params, 'Params must include clientInfo');

        // Assert: Verify the second message written is the 'notifications/initialized' notification
        $secondMessage = $writeStream->receive();
        $this->assertInstanceOf(JsonRpcMessage::class, $secondMessage, 'Second message should be a JsonRpcMessage');
        $this->assertInstanceOf(JSONRPCNotification::class, $secondMessage->message, 'Second message should be a JSON-RPC notification');

        $secondMessageData = json_decode(json_encode($secondMessage), true);
        $this->assertEquals('2.0', $secondMessageData['jsonrpc'], 'JSON-RPC version must be 2.0');
        $this->assertEquals('notifications/initialized', $secondMessageData['method'], 'Second notification method must be "notifications/initialized"');
        $this->assertArrayNotHasKey('id', $secondMessageData, 'Notifications must not have an ID');

        // Assert: Verify the write stream is now empty (no extra messages)
        $this->assertNull($writeStream->receive(), 'No additional messages should be sent after initialization');
    }

    /**
     * Test that getInitializeResult() succeeds after initialization.
     *
     * Verifies that the InitializeResult returned by the server is
     * correctly stored and accessible via getInitializeResult().
     */
    public function testGetInitializeResultSucceedsAfterInitialization(): void
    {
        // Arrange
        $readStream = new MemoryStream();
        $writeStream = new MemoryStream();

        $resultData = [
            'protocolVersion' => Version::LATEST_PROTOCOL_VERSION,
            'capabilities' => [],
            'serverInfo' => [
                'name' => 'test-server',
                'version' => '1.0.0'
            ]
        ];

        $readStream->send($this->createResponse($resultData));
        $session = new ClientSession($readStream, $writeStream, readTimeout: 2.0);

        // Act
        $session->initialize();
        $result = $session->getInitializeResult();

        // Assert
        $this->assertInstanceOf(InitializeResult::class, $result, 'Should return InitializeResult');
        $this->assertEquals(Version::LATEST_PROTOCOL_VERSION, $result->protocolVersion, 'Protocol version should match');
        $this->assertEquals('test-server', $result->serverInfo->name, 'Server name should match');
        $this->assertEquals('1.0.0', $result->serverInfo->version, 'Server version should match');
    }

    /**
     * Test that getNegotiatedProtocolVersion() succeeds after initialization.
     *
     * Verifies that the protocol version is correctly negotiated and
     * accessible after successful initialization.
     */
    public function testGetNegotiatedProtocolVersionSucceedsAfterInitialization(): void
    {
        // Arrange
        $readStream = new MemoryStream();
        $writeStream = new MemoryStream();

        $resultData = [
            'protocolVersion' => Version::LATEST_PROTOCOL_VERSION,
            'capabilities' => [],
            'serverInfo' => [
                'name' => 'test-server',
                'version' => '1.0.0'
            ]
        ];

        $readStream->send($this->createResponse($resultData));
        $session = new ClientSession($readStream, $writeStream, readTimeout: 2.0);

        // Act
        $session->initialize();
        $negotiatedVersion = $session->getNegotiatedProtocolVersion();

        // Assert
        $this->assertEquals(Version::LATEST_PROTOCOL_VERSION, $negotiatedVersion, 'Negotiated version should match server response');
    }

    /**
     * Test that supportsFeature('batch_messages') returns true for version 2025-03-26.
     *
     * The 'batch_messages' feature is supported in protocol version 2025-03-26 and later.
     * This test verifies that feature detection correctly identifies support.
     */
    public function testSupportsFeatureBatchMessagesReturnsTrueForLatestVersion(): void
    {
        // Arrange
        $readStream = new MemoryStream();
        $writeStream = new MemoryStream();

        $resultData = [
            'protocolVersion' => Version::LATEST_PROTOCOL_VERSION, // 2025-03-26
            'capabilities' => [],
            'serverInfo' => [
                'name' => 'test-server',
                'version' => '1.0.0'
            ]
        ];

        $readStream->send($this->createResponse($resultData));
        $session = new ClientSession($readStream, $writeStream, readTimeout: 2.0);

        // Act
        $session->initialize();
        $supportsBatchMessages = $session->supportsFeature('batch_messages');

        // Assert
        $this->assertTrue($supportsBatchMessages, 'Protocol version 2025-03-26 should support batch_messages');
    }

    /**
     * Test that initialization fails when server returns unsupported protocol version.
     *
     * The client should reject protocol versions that are not in the
     * SUPPORTED_PROTOCOL_VERSIONS list.
     */
    public function testInitializeRejectsUnsupportedProtocolVersion(): void
    {
        // Arrange
        $readStream = new MemoryStream();
        $writeStream = new MemoryStream();

        // Server responds with an unsupported protocol version
        $resultData = [
            'protocolVersion' => '2099-99-99', // Unsupported future version
            'capabilities' => [],
            'serverInfo' => [
                'name' => 'test-server',
                'version' => '1.0.0'
            ]
        ];

        $readStream->send($this->createResponse($resultData));
        $session = new ClientSession($readStream, $writeStream, readTimeout: 2.0);

        // Act & Assert
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Unsupported protocol version from server: 2099-99-99');
        $session->initialize();
    }

    /**
     * Test that supportsFeature() returns false before initialization.
     *
     * Before the session is initialized, no protocol version is negotiated,
     * so all features should be reported as unsupported.
     */
    public function testSupportsFeatureReturnsFalseBeforeInitialization(): void
    {
        // Arrange
        $readStream = new MemoryStream();
        $writeStream = new MemoryStream();
        $session = new ClientSession($readStream, $writeStream);

        // Act & Assert
        $this->assertFalse($session->supportsFeature('batch_messages'), 'Features should not be supported before initialization');
        $this->assertFalse($session->supportsFeature('audio_content'), 'Features should not be supported before initialization');
        $this->assertFalse($session->supportsFeature('annotations'), 'Features should not be supported before initialization');
    }

    private function createResponse(array $resultData): JsonRpcMessage
    {
        return new JsonRpcMessage(
            new JSONRPCResponse(
                jsonrpc: '2.0',
                id: new RequestId(0),
                result: $resultData
            )
        );
    }
}
