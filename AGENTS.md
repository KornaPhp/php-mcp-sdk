# AGENTS.md

## Project Overview

This is a PHP implementation of the Model Context Protocol (MCP), allowing applications to provide context for LLMs in a standardized way. The SDK implements both MCP clients and servers with support for stdio and HTTP transports.

**Key characteristics:**
- Designed for native PHP with easy installation via Composer
- Targets PHP 8.1+ with type safety (strict_types=1)
- Supports both traditional CLI/stdio and web hosting environments

## Development Commands

### Testing
```bash
# Run all tests
./vendor/bin/phpunit

# Run specific test file
./vendor/bin/phpunit tests/Server/ServerSessionTest.php

# Run specific test method
./vendor/bin/phpunit --filter testMethodName tests/Server/ServerSessionTest.php
```

### Installation & Dependencies
```bash
# Install dependencies
composer install

# Update dependencies
composer update

# Install optional logging support (required for webclient and some examples)
composer require monolog/monolog
```

### Running Examples
```bash
# Run stdio server example
php examples/server_stdio.php

# Run stdio client example (connects to server_stdio.php)
php examples/client_stdio.php

# Run HTTP server (requires web server)
php -S localhost:8000 examples/server_http.php

# Run HTTP client (connects to HTTP server)
php examples/client_http.php
```

## Architecture Overview

### Core Component Layers

1. **Session Layer** (`Shared/BaseSession.php`)
   - Abstract base for all MCP sessions (client and server)
   - Manages JSON-RPC message routing and handler registration
   - Handles request/response matching via request IDs
   - Maintains initialization state and protocol version negotiation

2. **Client Architecture** (`Client/`)
   - `Client`: Main entry point, detects transport (stdio vs HTTP) based on commandOrUrl parameter
   - `ClientSession`: Extends BaseSession, provides high-level methods (`listPrompts()`, `callTool()`, etc.)
   - `Transport/StdioTransport`: Process-based transport using stdin/stdout
   - `Transport/StreamableHttpTransport`: HTTP/HTTPS transport with SSE support
   - Both transports speak JSON-RPC over their respective channels

3. **Server Architecture** (`Server/`)
   - `Server`: Request/notification handler registry, capability management
   - `ServerSession`: Extends BaseSession, handles initialization handshake
   - `ServerRunner`: Stdio runner that manages the server lifecycle
   - `HttpServerRunner`: HTTP runner for web-based servers
   - Handlers are registered as callables: `registerHandler(string $method, callable $handler)`

4. **Types System** (`Types/`)
   - All MCP protocol types are implemented as typed PHP classes
   - Types implement `McpModel` interface for JSON serialization/deserialization
   - Uses `ExtraFieldsTrait` for forward compatibility with unknown fields
   - Request/Response types follow JSON-RPC 2.0 specification

5. **Transport Abstraction**
   - Stdio: Uses PHP process control (pcntl) for server process management
   - HTTP: Supports both standard HTTP and Server-Sent Events (SSE) for streaming
   - `MemoryStream` and `MemoryTransport` for testing without actual I/O

### Handler Registration Pattern

**Server-side:**
```php
$server->registerHandler('prompts/list', function($params): ListPromptsResult {
    // Return typed Result object
    return new ListPromptsResult([/* prompts */]);
});

$server->registerHandler('prompts/get', function(GetPromptRequestParams $params): GetPromptResult {
    // Type-hint params for automatic deserialization
    return new GetPromptResult(/* ... */);
});
```

**Client-side:**
```php
// ClientSession provides convenience methods that internally send JSON-RPC requests
$prompts = $session->listPrompts();
$result = $session->callTool($toolName, $arguments);
```

### Protocol Version Negotiation

The SDK implements MCP spec version negotiation in `BaseSession`:
- Server advertises supported versions in initialization response
- Client requests specific protocol version in initialization request
- Session negotiates to highest mutually supported version
- Falls back to older versions for backward compatibility
- Current implementation targets 2025-03-26 spec revision

### Web Hosting Considerations

The SDK includes special support for typical PHP web hosting:
- **Stateless mode**: Web client reinitializes connection per request (limitation of web hosting)
- HTTP transport designed to work without long-running processes
- Uses session files or other persistence for maintaining state across requests
- See `webclient/` directory for reference implementation

## Testing Patterns

Tests use PHPUnit 10+ and follow these conventions:

- Test classes are marked `final` and extend `PHPUnit\Framework\TestCase`
- Test methods include detailed docblocks explaining what is being validated
- Mock transports using `MemoryTransport` for isolation
- Focus on protocol compliance and state transitions
- Test files mirror source structure: `tests/Server/ServerSessionTest.php` tests `src/Server/ServerSession.php`

## Important Implementation Notes

### Type Safety
- All files use `declare(strict_types=1);`
- Parameters and return types are strictly typed
- Use type hints on handler callables for automatic param deserialization

### Error Handling
- Protocol errors throw `Mcp\Shared\McpError`
- Transport errors throw `RuntimeException`
- Invalid parameters throw `InvalidArgumentException`
- Errors are automatically converted to JSON-RPC error responses

### Logging
- All major components accept optional PSR-3 `LoggerInterface`
- Defaults to `NullLogger` if not provided
- Examples use Monolog for demonstration

### OAuth Support
- HTTP transport includes OAuth 2.1 authorization framework
- Server-side implementation available in `Server/Auth/`
- Client-side implementation still in development
- See `examples/server_auth/` for usage

## MCP Protocol Capabilities

Servers expose capabilities through handler registration:
- **Prompts**: `prompts/list`, `prompts/get`
- **Resources**: `resources/list`, `resources/read`, `resources/subscribe`
- **Tools**: `tools/list`, `tools/call`
- **Logging**: `logging/setLevel`

Capabilities are automatically detected based on registered handlers and included in initialization response.

## Common Patterns

### Creating a Server
1. Instantiate `Server` with a name
2. Register handlers for desired capabilities
3. Create `InitializationOptions` via `$server->createInitializationOptions()`
4. Pass server and options to `ServerRunner` (stdio) or `HttpServerRunner` (HTTP)
5. Call `$runner->run()` to start

### Creating a Client
1. Instantiate `Client`
2. Call `$client->connect()` with command/URL and parameters
3. Returns initialized `ClientSession`
4. Use session methods to interact with server
5. Call `$client->close()` when done

### Handler Params Type Hinting
When registering handlers, type-hint the params parameter to get automatic deserialization:
```php
$server->registerHandler('tools/call', function(CallToolRequestParams $params): CallToolResult {
    // $params is automatically deserialized from JSON
    $toolName = $params->name;
    $arguments = $params->arguments;
    // ...
});
```
