# Logging System - Notematic API

## Overview
The Notematic API uses a comprehensive logging system based on the `log` and `tracing` crates to provide detailed debugging and monitoring capabilities.

## Log Levels

### Available Log Levels
- **ERROR**: Critical errors that prevent normal operation
- **WARN**: Warning conditions that might indicate problems
- **INFO**: General information about application flow
- **DEBUG**: Detailed debugging information
- **TRACE**: Very detailed debugging information

## Configuration

### Environment Variables
Set the following environment variables to control logging:

```bash
# Set log level for all modules
RUST_LOG=info

# Set specific log levels for different modules
RUST_LOG=info,notematic_api=debug,actix_web=info

# Development with full debug logging
RUST_LOG=debug,notematic_api=trace
```

### Common Log Level Configurations

#### Production
```bash
RUST_LOG=warn,notematic_api=info
```

#### Development
```bash
RUST_LOG=info,notematic_api=debug
```

#### Debugging
```bash
RUST_LOG=debug,notematic_api=trace
```

## What Gets Logged

### Authentication & Authorization
- Login attempts (IP, username)
- Registration attempts (IP, username)
- JWT token generation and verification
- Rate limiting violations
- Invalid token attempts

### API Operations
- Request processing (endpoint, method, status)
- Database operations (CouchDB interactions)
- Error responses with details
- Performance metrics

### Security Events
- Rate limit exceeded attempts
- Invalid authentication attempts
- Suspicious activity patterns

## Running with Logging

### Development
```bash
cd notematic-api
RUST_LOG=info cargo run
```

### Production
```bash
cd notematic-api
RUST_LOG=warn cargo run --release
```

### Debug Mode
```bash
cd notematic-api
RUST_LOG=debug cargo run
```

## Log Output Format

Logs are formatted with:
- Timestamp
- Log level
- Module path
- Message
- Additional context (IP addresses, user IDs, etc.)

Example:
```
2024-01-15T10:30:45.123Z INFO  notematic_api::handlers Registration attempt from IP: 127.0.0.1
2024-01-15T10:30:45.124Z DEBUG notematic_api::utils Password hashed successfully
2024-01-15T10:30:45.125Z INFO  notematic_api::handlers User registered successfully: testuser
```

## Monitoring and Debugging

### Common Issues to Monitor
1. **Rate Limiting**: Watch for repeated rate limit violations
2. **Authentication Failures**: Monitor failed login attempts
3. **Database Errors**: Track CouchDB connection issues
4. **JWT Issues**: Monitor token generation/verification failures

### Debugging Tips
1. Use `RUST_LOG=debug` to see detailed request processing
2. Monitor rate limiting with `RUST_LOG=info` to see IP-based limits
3. Check JWT middleware logs for authentication issues
4. Use `RUST_LOG=trace` for maximum detail (development only)

## Integration with External Logging

The logging system can be easily integrated with external logging services by:
1. Redirecting stdout/stderr to log aggregation services
2. Using log forwarding tools
3. Implementing custom log handlers for specific requirements 