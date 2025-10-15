"""
Pytest configuration and shared fixtures for BOAZ MCP Server tests
"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from boaz_mcp_server import MCPServer


@pytest.fixture
def server():
    """Provide a fresh MCPServer instance for each test"""
    return MCPServer()


@pytest.fixture
def valid_generate_loader_request():
    """Provide a valid generate_loader request"""
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "generate_loader",
            "arguments": {
                "input_file": "test.exe",
                "output_file": "output.exe",
                "loader": 16,
                "shellcode_type": "donut"
            }
        }
    }


@pytest.fixture
def valid_initialize_request():
    """Provide a valid initialize request"""
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }


@pytest.fixture
def valid_tools_list_request():
    """Provide a valid tools/list request"""
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    }


@pytest.fixture
def sample_configs():
    """Provide sample BOAZ configurations for testing"""
    return {
        "minimal": {
            "loader": 16,
            "shellcode_type": "donut"
        },
        "full": {
            "input_file": "test.exe",
            "output_file": "output.exe",
            "loader": 73,
            "shellcode_type": "amber",
            "encoding": "aes",
            "compiler": "akira",
            "obfuscate": True,
            "anti_emulation": True,
            "etw_patching": True
        },
        "invalid_loader": {
            "loader": 999,
            "shellcode_type": "donut"
        },
        "invalid_encoding": {
            "loader": 16,
            "shellcode_type": "donut",
            "encoding": "invalid"
        }
    }


@pytest.fixture
def dangerous_paths():
    """Provide dangerous path patterns for security testing"""
    return [
        "../etc/passwd",
        "../../sensitive/file",
        "/etc/passwd",
        "/var/log/sensitive.log",
        "safe/../../../etc/passwd",
        "/root/.ssh/id_rsa",
        "..\\windows\\system32\\config\\sam",
        "C:\\Windows\\System32\\cmd.exe"
    ]


@pytest.fixture
def safe_paths():
    """Provide safe path patterns for testing"""
    return [
        "output/file.exe",
        "test.bin",
        "subdir/file.exe",
        "my_output.exe",
        "loaders/loader_16.exe"
    ]


@pytest.fixture
def command_injection_patterns():
    """Provide command injection patterns for testing"""
    return [
        "file.exe; rm -rf /",
        "file.exe | cat /etc/passwd",
        "file.exe && malicious",
        "file.exe `whoami`",
        "file.exe $(whoami)",
        "file.exe > /tmp/output",
        "file.exe < /tmp/input",
        "file.exe\nrm -rf /",
        "file.exe || echo pwned"
    ]


# Pytest hooks for custom behavior

def pytest_configure(config):
    """Configure pytest with custom markers"""
    config.addinivalue_line(
        "markers", "protocol: mark test as testing MCP protocol compliance"
    )
    config.addinivalue_line(
        "markers", "security: mark test as testing security features"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as testing BOAZ integration"
    )
    config.addinivalue_line(
        "markers", "tools: mark test as testing MCP tools"
    )


def pytest_collection_modifyitems(config, items):
    """Automatically add markers based on test file names"""
    for item in items:
        if "test_mcp_protocol" in str(item.fspath):
            item.add_marker(pytest.mark.protocol)
        elif "test_security" in str(item.fspath):
            item.add_marker(pytest.mark.security)
        elif "test_boaz_integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        elif "test_tools" in str(item.fspath):
            item.add_marker(pytest.mark.tools)


def pytest_report_header(config):
    """Add custom header to pytest output"""
    return [
        "BOAZ MCP Server Test Suite",
        "Testing MCP protocol compliance, security, and functionality"
    ]
