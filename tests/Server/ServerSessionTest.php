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

namespace Mcp\Tests\Server;

use Mcp\Server\InitializationOptions;
use Mcp\Server\InitializationState;
use Mcp\Server\ServerSession;
use Mcp\Server\Transport\Transport;
use Mcp\Shared\RequestResponder;
use Mcp\Shared\Version;
use Mcp\Types\ClientCapabilities;
use Mcp\Types\ClientRequest;
use Mcp\Types\Implementation;
use Mcp\Types\InitializeRequest;
use Mcp\Types\InitializeRequestParams;
use Mcp\Types\InitializeResult;
use Mcp\Types\JsonRpcMessage;
use Mcp\Types\JSONRPCResponse;
use Mcp\Types\RequestId;
use Mcp\Types\ServerCapabilities;
use PHPUnit\Framework\TestCase;

/**
 * Tests for ServerSession initialization and protocol version negotiation.
 *
 * Validates that the server correctly:
 * - Receives 'initialize' requests from clients
 * - Negotiates protocol versions based on client capabilities
 * - Responds with InitializeResult containing negotiated version
 * - Transitions through proper initialization states
 * - Stores client parameters and negotiated protocol version
 * - Handles version downgrade when client requests older supported version
 * - Handles version fallback when client requests unsupported version
 *
 * Critical for ensuring servers can communicate with clients using
 * different protocol versions (backward compatibility).
 */
final class ServerSessionTest extends TestCase
{
    /**
     * Test that server negotiates to an older protocol version when requested.
     *
     * Protocol version negotiation scenario:
     * - Client requests: '2024-11-05' (older but supported version)
     * - Server prefers: '2025-03-26' (latest version)
     * - Expected result: Server should accept '2024-11-05' (common ground)
     *
     * This validates backward compatibility - servers must support clients
     * running older SDK versions.
     *
     * Corresponds to ServerSession.php:268-269 (supported version branch)
     */
    public function testInitializeNegotiatesCommonProtocolVersion(): void
    {
        // Arrange: Create server session with in-memory transport
        $transport = new InMemoryTransport();
        $session = $this->createSession($transport);

        // Use the first (oldest) supported protocol version for this test
        // SUPPORTED_PROTOCOL_VERSIONS = ['2024-11-05', '2025-03-26']
        $clientRequestedVersion = Version::SUPPORTED_PROTOCOL_VERSIONS[0];

        // Verify test assumptions: ensure we're actually testing version downgrade
        $this->assertNotSame(
            Version::LATEST_PROTOCOL_VERSION,
            $clientRequestedVersion,
            'Test setup assumes an older supported protocol exists'
        );

        // Create a mock initialize request from the client
        $request = $this->createInitializeClientRequest($clientRequestedVersion);

        // Create the responder context (simulates BaseSession's request handling)
        $responder = new RequestResponder(
            requestId: new RequestId(7),
            params: [
                'protocolVersion' => $clientRequestedVersion,
                'capabilities' => [],
                'clientInfo' => [
                    'name' => 'test-client',
                    'version' => '0.1.0',
                ],
            ],
            request: $request,
            session: $session
        );

        // Act: Handle the initialize request
        $session->handleRequest($responder);

        // Assert: Verify server sent exactly one response
        $written = $transport->writtenMessages;
        $this->assertCount(1, $written, 'Server should respond exactly once');

        // Verify response structure and type
        $responseMessage = $written[0];
        $this->assertInstanceOf(JsonRpcMessage::class, $responseMessage);
        $this->assertInstanceOf(JSONRPCResponse::class, $responseMessage->message);
        $this->assertInstanceOf(InitializeResult::class, $responseMessage->message->result);

        // Verify the negotiated protocol version in the response
        $this->assertSame(
            $clientRequestedVersion,
            $responseMessage->message->result->protocolVersion,
            'Server response should reflect negotiated protocol (client requested version)'
        );

        // Verify internal state: negotiatedProtocolVersion is stored correctly
        $this->assertSame(
            $clientRequestedVersion,
            $this->readProperty($session, 'negotiatedProtocolVersion'),
            'Server should store the negotiated protocol version'
        );

        // Verify state transition: should be in Initialized state
        $this->assertSame(
            InitializationState::Initialized,
            $this->readProperty($session, 'initializationState'),
            'Server should transition to Initialized state after handling initialize request'
        );
    }

    /**
     * Test that server accepts the latest protocol version when requested.
     *
     * Protocol version negotiation scenario:
     * - Client requests: '2025-03-26' (latest version)
     * - Server prefers: '2025-03-26' (latest version)
     * - Expected result: Server should accept '2025-03-26' (perfect match)
     *
     * This is the happy path where client and server are both on the latest version.
     *
     * Corresponds to ServerSession.php:263-264 (latest version branch)
     */
    public function testInitializeAcceptsLatestProtocolVersion(): void
    {
        // Arrange: Create server session
        $transport = new InMemoryTransport();
        $session = $this->createSession($transport);

        // Client requests the latest protocol version
        $clientRequestedVersion = Version::LATEST_PROTOCOL_VERSION;

        // Create mock initialize request
        $request = $this->createInitializeClientRequest($clientRequestedVersion);

        $responder = new RequestResponder(
            requestId: new RequestId(1),
            params: [
                'protocolVersion' => $clientRequestedVersion,
                'capabilities' => [],
                'clientInfo' => [
                    'name' => 'modern-client',
                    'version' => '2.0.0',
                ],
            ],
            request: $request,
            session: $session
        );

        // Act: Handle the initialize request
        $session->handleRequest($responder);

        // Assert: Verify server responds with latest version
        $written = $transport->writtenMessages;
        $this->assertCount(1, $written, 'Server should respond exactly once');

        $responseMessage = $written[0];
        $this->assertInstanceOf(InitializeResult::class, $responseMessage->message->result);

        $this->assertSame(
            Version::LATEST_PROTOCOL_VERSION,
            $responseMessage->message->result->protocolVersion,
            'Server should accept and return latest protocol version'
        );

        // Verify internal state
        $this->assertSame(
            Version::LATEST_PROTOCOL_VERSION,
            $this->readProperty($session, 'negotiatedProtocolVersion'),
            'Server should store latest protocol version'
        );

        $this->assertSame(
            InitializationState::Initialized,
            $this->readProperty($session, 'initializationState'),
            'Server should transition to Initialized state'
        );
    }

    /**
     * Test that server falls back to latest when client requests unsupported version.
     *
     * Protocol version negotiation scenario:
     * - Client requests: '2099-99-99' (unsupported future version)
     * - Server supports: ['2024-11-05', '2025-03-26']
     * - Expected result: Server should fallback to '2025-03-26' (latest supported)
     *
     * This validates that servers can handle clients requesting unknown/future
     * protocol versions by falling back to the latest version the server supports.
     *
     * Corresponds to ServerSession.php:272-276 (unsupported version fallback)
     */
    public function testInitializeFallsBackToLatestForUnsupportedVersion(): void
    {
        // Arrange: Create server session
        $transport = new InMemoryTransport();
        $session = $this->createSession($transport);

        // Client requests an unsupported (future) protocol version
        $clientRequestedVersion = '2099-99-99';

        // Verify test assumptions: version is actually unsupported
        $this->assertNotContains(
            $clientRequestedVersion,
            Version::SUPPORTED_PROTOCOL_VERSIONS,
            'Test setup assumes version is not in supported list'
        );

        // Create mock initialize request with unsupported version
        $request = $this->createInitializeClientRequest($clientRequestedVersion);

        $responder = new RequestResponder(
            requestId: new RequestId(2),
            params: [
                'protocolVersion' => $clientRequestedVersion,
                'capabilities' => [],
                'clientInfo' => [
                    'name' => 'future-client',
                    'version' => '99.0.0',
                ],
            ],
            request: $request,
            session: $session
        );

        // Act: Handle the initialize request
        $session->handleRequest($responder);

        // Assert: Verify server falls back to latest supported version
        $written = $transport->writtenMessages;
        $this->assertCount(1, $written, 'Server should respond exactly once');

        $responseMessage = $written[0];
        $this->assertInstanceOf(InitializeResult::class, $responseMessage->message->result);

        $this->assertSame(
            Version::LATEST_PROTOCOL_VERSION,
            $responseMessage->message->result->protocolVersion,
            'Server should fallback to latest supported version for unsupported client version'
        );

        // Verify internal state uses fallback version
        $this->assertSame(
            Version::LATEST_PROTOCOL_VERSION,
            $this->readProperty($session, 'negotiatedProtocolVersion'),
            'Server should store latest protocol version as fallback'
        );

        $this->assertSame(
            InitializationState::Initialized,
            $this->readProperty($session, 'initializationState'),
            'Server should transition to Initialized state even with version fallback'
        );
    }

    /**
     * Test that server correctly populates InitializeResult with server info.
     *
     * Verifies that the InitializeResult response contains:
     * - Negotiated protocol version
     * - Server capabilities (from InitializationOptions)
     * - Server name and version (from InitializationOptions)
     *
     * Corresponds to ServerSession.php:243-250 (InitializeResult construction)
     */
    public function testInitializeReturnsCorrectServerInfo(): void
    {
        // Arrange: Create server session with specific server info
        $transport = new InMemoryTransport();
        $session = $this->createSession($transport);

        $clientRequestedVersion = Version::LATEST_PROTOCOL_VERSION;
        $request = $this->createInitializeClientRequest($clientRequestedVersion);

        $responder = new RequestResponder(
            requestId: new RequestId(3),
            params: [
                'protocolVersion' => $clientRequestedVersion,
                'capabilities' => [],
                'clientInfo' => [
                    'name' => 'test-client',
                    'version' => '1.0.0',
                ],
            ],
            request: $request,
            session: $session
        );

        // Act: Handle the initialize request
        $session->handleRequest($responder);

        // Assert: Verify InitializeResult contains correct server info
        $written = $transport->writtenMessages;
        $responseMessage = $written[0];

        /** @var InitializeResult $result */
        $result = $responseMessage->message->result;

        $this->assertSame(
            'test-server',
            $result->serverInfo->name,
            'InitializeResult should contain server name from InitializationOptions'
        );

        $this->assertSame(
            '1.0.0',
            $result->serverInfo->version,
            'InitializeResult should contain server version from InitializationOptions'
        );

        $this->assertInstanceOf(
            ServerCapabilities::class,
            $result->capabilities,
            'InitializeResult should contain ServerCapabilities from InitializationOptions'
        );
    }

    /**
     * Create a test ServerSession with standard initialization options.
     *
     * @param InMemoryTransport $transport The transport to use for the session
     * @return ServerSession The configured server session
     */
    private function createSession(InMemoryTransport $transport): ServerSession
    {
        $options = new InitializationOptions(
            serverName: 'test-server',
            serverVersion: '1.0.0',
            capabilities: new ServerCapabilities()
        );

        return new ServerSession($transport, $options);
    }

    /**
     * Create a mock initialize request from a client.
     *
     * @param string $protocolVersion The protocol version the client requests
     * @return ClientRequest The mock client request
     */
    private function createInitializeClientRequest(string $protocolVersion): ClientRequest
    {
        $params = new InitializeRequestParams(
            protocolVersion: $protocolVersion,
            capabilities: new ClientCapabilities(),
            clientInfo: new Implementation('test-client', '0.1.0')
        );

        return new ClientRequest(new InitializeRequest($params));
    }

    /**
     * Use reflection to read private/protected properties for testing.
     *
     * @param object $object The object to read from
     * @param string $property The property name to read
     * @return mixed The property value
     */
    private function readProperty(object $object, string $property): mixed
    {
        $reflection = new \ReflectionProperty($object, $property);
        $reflection->setAccessible(true);
        return $reflection->getValue($object);
    }
}

/**
 * In-memory transport implementation for testing ServerSession.
 *
 * This mock transport captures all messages written by the ServerSession
 * so tests can inspect the exact responses sent to clients.
 *
 * Unlike MemoryStream (used for client tests), this implements the
 * Transport interface which ServerSession requires.
 */
final class InMemoryTransport implements Transport
{
    /** @var JsonRpcMessage[] Messages written by ServerSession */
    public array $writtenMessages = [];

    /**
     * No-op start method (required by Transport interface).
     */
    public function start(): void
    {
        // No-op for tests
    }

    /**
     * No-op stop method (required by Transport interface).
     */
    public function stop(): void
    {
        // No-op for tests
    }

    /**
     * Returns null - tests don't simulate incoming messages via transport.
     * Instead, tests call handleRequest() directly.
     */
    public function readMessage(): ?JsonRpcMessage
    {
        return null;
    }

    /**
     * Capture messages written by ServerSession for inspection.
     *
     * @param JsonRpcMessage $message The message to write
     */
    public function writeMessage(JsonRpcMessage $message): void
    {
        $this->writtenMessages[] = $message;
    }
}
