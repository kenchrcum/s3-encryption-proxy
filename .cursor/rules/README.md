# Cursor Rules for S3 Encryption Gateway

This directory contains Cursor IDE rules and guidelines for the S3 Encryption Gateway project.

## Files

- `go-conventions.md` - Go coding conventions and best practices
- `security.md` - Security guidelines and cryptographic requirements
- `project-structure.md` - Package organization and project structure rules
- `README.md` - This file

## Installation

To use these rules in Cursor:

1. Copy the `.cursorrules` file from the project root to your project root
2. Copy the contents of this `cursor-rules/` directory to `.cursor/rules/` in your project

```bash
# From project root
cp .cursorrules ~/.cursor/rules/  # or wherever your Cursor config is
cp -r cursor-rules/* .cursor/rules/
```

## Rule Categories

### Go Conventions
- Naming conventions (PascalCase, camelCase)
- Import organization
- Error handling patterns
- Interface design principles
- Concurrency patterns
- Memory management
- Testing patterns

### Security Guidelines
- Cryptographic requirements (AES-256-GCM, PBKDF2)
- Key management and data protection
- Input validation
- Secure error handling
- Network security
- Access control

### Project Structure
- Package organization
- File naming conventions
- Interface design and location
- Dependency management
- Configuration patterns
- Error handling
- Testing organization

## Key Principles

### Security First
- Client-side encryption only (no server-side encryption trust)
- AES-256-GCM for authenticated encryption
- PBKDF2 key derivation with 100,000+ iterations
- Never log sensitive data (passwords, keys, decrypted content)

### API Compatibility
- Transparent S3 API proxy
- Full S3 operation support (GET, PUT, DELETE, LIST, HEAD)
- Header and metadata preservation
- Error code translation

### Performance & Reliability
- Streaming encryption/decryption for large objects
- Hardware-accelerated crypto where available
- Comprehensive error handling
- Structured logging and metrics

### Code Quality
- Comprehensive testing (unit, integration, security)
- Clear documentation and comments
- Consistent code style and organization
- Security-focused code reviews

## Development Workflow

1. **Planning**: Use provided architecture documents
2. **Implementation**: Follow coding conventions and security guidelines
3. **Testing**: Write comprehensive tests for all functionality
4. **Review**: Security and code quality reviews
5. **Deployment**: Use provided Docker/Kubernetes configurations

## Architecture Overview

The S3 Encryption Gateway consists of:

- **HTTP Server**: Receives S3 API requests
- **Encryption Engine**: AES-256-GCM encryption/decryption
- **S3 Backend**: Communication with actual S3 providers
- **Configuration**: Environment-based configuration
- **Monitoring**: Prometheus metrics and health checks

## Quick Start

1. Set up Go development environment
2. Clone the repository
3. Run `make dev` for development server
4. Run `make test` for testing
5. Use MinIO for local S3 testing

See DEVELOPMENT_GUIDE.md for detailed setup instructions.

## Contributing

- Follow all guidelines in these rules
- Write tests for new functionality
- Update documentation for API changes
- Security review for crypto-related changes
- Code review required for all changes

## Security Considerations

- **Never commit secrets**: Use environment variables or Kubernetes secrets
- **Validate all inputs**: Especially cryptographic parameters
- **Zero sensitive data**: Overwrite keys after use
- **Log safely**: Never log passwords or decrypted content
- **Regular audits**: Security review of all crypto code

These rules ensure consistent, secure, and maintainable code throughout the S3 Encryption Gateway project.