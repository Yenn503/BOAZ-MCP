# BOAZ MCP Server Test Suite

Comprehensive test suite for the BOAZ MCP (Model Context Protocol) server.

## Overview

This test suite provides complete coverage of:
- **MCP Protocol Compliance** - JSON-RPC 2.0 and MCP protocol adherence
- **Security Features** - Path traversal prevention, command injection prevention, input validation
- **BOAZ Integration** - Command generation and parameter handling
- **Tool Functionality** - All MCP tools (generate_loader, list_loaders, etc.)

## Test Files

### test_mcp_protocol.py
Tests MCP protocol compliance including:
- JSON-RPC 2.0 compliance
- Protocol version handling
- initialize, tools/list, tools/call methods
- Request/response structure
- Error codes and handling

### test_security.py
Tests security measures including:
- Path traversal attack prevention
- Command injection prevention
- Input validation for all parameters
- Required parameter enforcement
- Case-sensitive validation

### test_boaz_integration.py
Tests BOAZ tool integration including:
- Command generation for various configurations
- Loader support (1-77)
- Shellcode type support (donut, pe2sh, rc4, amber, shoggoth)
- Encoding support (uuid, aes, xor, etc.)
- Compiler support (mingw, pluto, akira)
- Configuration validation

### test_tools.py
Tests all MCP tools including:
- generate_loader tool
- list_loaders tool
- list_encodings tool
- list_shellcode_types tool
- validate_config tool
- Tool discovery and interoperability

## Installation

Install test dependencies:

```bash
pip install -r requirements.txt
```

Or if you prefer using a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Running Tests

### Run All Tests

```bash
./run_tests.sh
```

Or directly with pytest:

```bash
pytest tests/
```

### Run with Verbose Output

```bash
./run_tests.sh -v
```

### Run with Coverage Report

```bash
./run_tests.sh -c
```

This generates an HTML coverage report in `htmlcov/index.html`.

### Run Specific Test File

```bash
./run_tests.sh -t test_security.py
```

Or with pytest:

```bash
pytest tests/test_security.py
```

### Run Specific Test Class

```bash
pytest tests/test_security.py::TestPathTraversalPrevention
```

### Run Specific Test Method

```bash
pytest tests/test_security.py::TestPathTraversalPrevention::test_reject_parent_directory_traversal
```

### Run Tests in Parallel

```bash
pytest tests/ -n auto
```

## Test Organization

Tests are organized into classes by functionality:

```
test_mcp_protocol.py
├── TestJSONRPCCompliance
├── TestMCPInitialization
├── TestToolsList
├── TestToolsCall
└── TestErrorHandling

test_security.py
├── TestPathTraversalPrevention
├── TestCommandInjectionPrevention
├── TestInputValidation
├── TestRequiredParameters
└── TestCaseSensitivity

test_boaz_integration.py
├── TestCommandGeneration
├── TestLoaderSupport
├── TestShellcodeTypeSupport
├── TestEncodingSupport
├── TestCompilerSupport
└── TestConfigurationValidation

test_tools.py
├── TestGenerateLoaderTool
├── TestListLoadersTool
├── TestListEncodingsTool
├── TestListShellcodeTypesTool
├── TestValidateConfigTool
├── TestToolDiscovery
└── TestToolInteroperability
```

## Coverage Goals

The test suite aims for:
- 100% coverage of all MCP protocol methods
- 100% coverage of all security validation functions
- 100% coverage of all tool implementations
- Comprehensive edge case testing

## Writing New Tests

When adding new tests:

1. Follow the existing naming convention: `test_*.py`
2. Organize tests into classes by functionality
3. Use descriptive test names: `test_what_is_being_tested`
4. Include docstrings explaining what each test verifies
5. Use the setup_method for test fixtures
6. Follow AAA pattern: Arrange, Act, Assert

Example:

```python
class TestNewFeature:
    """Test new feature functionality"""

    def setup_method(self):
        """Setup test server instance"""
        self.server = MCPServer()

    def test_feature_does_something(self):
        """Test that feature does something specific"""
        # Arrange
        request = {...}

        # Act
        response = self.server.handle_request(request)

        # Assert
        assert "result" in response
```

## Continuous Integration

These tests are designed to run in CI/CD pipelines. Example GitHub Actions workflow:

```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      - run: pip install -r tests/requirements.txt
      - run: pytest tests/ --cov=boaz_mcp_server --cov-report=xml
      - uses: codecov/codecov-action@v3
```

## Troubleshooting

### Import Errors

If you get import errors, ensure you're running tests from the project root:

```bash
cd /path/to/BOAZ-MCP
pytest tests/
```

### Missing Dependencies

Install all dependencies:

```bash
pip install -r tests/requirements.txt
```

### Permission Denied on run_tests.sh

Make the script executable:

```bash
chmod +x tests/run_tests.sh
```

## Additional Resources

- [pytest Documentation](https://docs.pytest.org/)
- [MCP Protocol Specification](https://modelcontextprotocol.io/)
- [JSON-RPC 2.0 Specification](https://www.jsonrpc.org/specification)
- [BOAZ Tool Documentation](../BOAZ_beta/README.md)

## Contributing

When contributing tests:
1. Ensure all existing tests pass
2. Add tests for new features
3. Maintain or improve code coverage
4. Follow the existing code style
5. Update this README if adding new test categories
