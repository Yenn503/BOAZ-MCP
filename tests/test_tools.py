"""
Test All MCP Tools
Tests each MCP tool functionality (generate_loader, list_loaders, list_encodings, etc.)
"""

import pytest
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from boaz_mcp_server import MCPServer


class TestGenerateLoaderTool:
    """Test generate_loader tool functionality"""

    def setup_method(self):
        self.server = MCPServer()

    def test_generate_loader_success(self):
        """Test successful loader generation request"""
        request = {
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
        response = self.server.handle_request(request)

        assert "result" in response
        assert "content" in response["result"]
        assert len(response["result"]["content"]) > 0
        assert response["result"]["content"][0]["type"] == "text"

    def test_generate_loader_with_all_parameters(self):
        """Test loader generation with all parameters"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "generate_loader",
                "arguments": {
                    "input_file": "test.exe",
                    "output_file": "output.exe",
                    "loader": 73,
                    "shellcode_type": "amber",
                    "encoding": "aes",
                    "compiler": "akira",
                    "obfuscate": True,
                    "anti_emulation": True,
                    "etw_patching": True
                }
            }
        }
        response = self.server.handle_request(request)

        assert "result" in response
        content = response["result"]["content"][0]["text"]
        # Verify all parameters are in the command
        assert "test.exe" in content
        assert "output.exe" in content
        assert "73" in content
        assert "amber" in content
        assert "aes" in content
        assert "akira" in content

    def test_generate_loader_minimal_parameters(self):
        """Test loader generation with only required parameters"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "generate_loader",
                "arguments": {
                    "input_file": "minimal.exe",
                    "output_file": "out.exe",
                    "loader": 1,
                    "shellcode_type": "donut"
                }
            }
        }
        response = self.server.handle_request(request)

        assert "result" in response
        assert "error" not in response

    def test_generate_loader_returns_command(self):
        """Test that generate_loader returns the command string"""
        request = {
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
        response = self.server.handle_request(request)

        content = response["result"]["content"][0]["text"]
        assert "Command prepared:" in content
        assert "Boaz.py" in content


class TestListLoadersTool:
    """Test list_loaders tool functionality"""

    def setup_method(self):
        self.server = MCPServer()

    def test_list_loaders_success(self):
        """Test successful list_loaders request"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "list_loaders",
                "arguments": {}
            }
        }
        response = self.server.handle_request(request)

        assert "result" in response
        assert "error" not in response

    def test_list_loaders_returns_content(self):
        """Test list_loaders returns content array"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "list_loaders",
                "arguments": {}
            }
        }
        response = self.server.handle_request(request)

        assert "content" in response["result"]
        assert isinstance(response["result"]["content"], list)
        assert len(response["result"]["content"]) > 0

    def test_list_loaders_content_structure(self):
        """Test list_loaders content has correct structure"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "list_loaders",
                "arguments": {}
            }
        }
        response = self.server.handle_request(request)

        content_item = response["result"]["content"][0]
        assert "type" in content_item
        assert "text" in content_item
        assert content_item["type"] == "text"

    def test_list_loaders_contains_loader_info(self):
        """Test list_loaders returns loader information"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "list_loaders",
                "arguments": {}
            }
        }
        response = self.server.handle_request(request)

        text = response["result"]["content"][0]["text"]
        # Should contain loader numbers and descriptions
        assert "1:" in text or "Loader" in text
        assert len(text) > 50  # Should have substantial content

    def test_list_loaders_no_parameters_required(self):
        """Test list_loaders works without parameters"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "list_loaders",
                "arguments": {}
            }
        }
        response = self.server.handle_request(request)

        assert "result" in response
        assert "error" not in response


class TestListEncodingsTool:
    """Test list_encodings tool functionality"""

    def setup_method(self):
        self.server = MCPServer()

    def test_list_encodings_success(self):
        """Test successful list_encodings request"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "list_encodings",
                "arguments": {}
            }
        }
        response = self.server.handle_request(request)

        assert "result" in response
        assert "error" not in response

    def test_list_encodings_returns_content(self):
        """Test list_encodings returns content array"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "list_encodings",
                "arguments": {}
            }
        }
        response = self.server.handle_request(request)

        assert "content" in response["result"]
        assert isinstance(response["result"]["content"], list)
        assert len(response["result"]["content"]) > 0

    def test_list_encodings_contains_encoding_info(self):
        """Test list_encodings returns encoding information"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "list_encodings",
                "arguments": {}
            }
        }
        response = self.server.handle_request(request)

        text = response["result"]["content"][0]["text"]
        # Should contain various encoding types
        assert "uuid" in text.lower() or "UUID" in text
        assert "aes" in text.lower() or "AES" in text
        assert "xor" in text.lower() or "XOR" in text

    def test_list_encodings_includes_descriptions(self):
        """Test list_encodings includes descriptions"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "list_encodings",
                "arguments": {}
            }
        }
        response = self.server.handle_request(request)

        text = response["result"]["content"][0]["text"]
        # Should have descriptions, not just names
        assert "-" in text or ":" in text
        assert len(text) > 100


class TestListShellcodeTypesTool:
    """Test list_shellcode_types tool functionality"""

    def setup_method(self):
        self.server = MCPServer()

    def test_list_shellcode_types_success(self):
        """Test successful list_shellcode_types request"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "list_shellcode_types",
                "arguments": {}
            }
        }
        response = self.server.handle_request(request)

        assert "result" in response
        assert "error" not in response

    def test_list_shellcode_types_returns_content(self):
        """Test list_shellcode_types returns content array"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "list_shellcode_types",
                "arguments": {}
            }
        }
        response = self.server.handle_request(request)

        assert "content" in response["result"]
        assert isinstance(response["result"]["content"], list)

    def test_list_shellcode_types_contains_types(self):
        """Test list_shellcode_types contains shellcode types"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "list_shellcode_types",
                "arguments": {}
            }
        }
        response = self.server.handle_request(request)

        text = response["result"]["content"][0]["text"]
        # Should contain known shellcode types
        assert "donut" in text.lower()
        assert "amber" in text.lower()
        assert "shoggoth" in text.lower()

    def test_list_shellcode_types_includes_descriptions(self):
        """Test list_shellcode_types includes descriptions"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "list_shellcode_types",
                "arguments": {}
            }
        }
        response = self.server.handle_request(request)

        text = response["result"]["content"][0]["text"]
        # Should have descriptions
        assert "-" in text or ":" in text
        assert len(text) > 50


class TestValidateConfigTool:
    """Test validate_config tool functionality"""

    def setup_method(self):
        self.server = MCPServer()

    def test_validate_config_success(self):
        """Test successful config validation"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "validate_config",
                "arguments": {
                    "config": {
                        "loader": 16,
                        "shellcode_type": "donut"
                    }
                }
            }
        }
        response = self.server.handle_request(request)

        assert "result" in response
        assert "error" not in response

    def test_validate_config_returns_json(self):
        """Test validate_config returns JSON result"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "validate_config",
                "arguments": {
                    "config": {
                        "loader": 16,
                        "shellcode_type": "donut"
                    }
                }
            }
        }
        response = self.server.handle_request(request)

        text = response["result"]["content"][0]["text"]
        # Should be valid JSON
        result = json.loads(text)
        assert "valid" in result
        assert "errors" in result
        assert "warnings" in result

    def test_validate_config_valid_configuration(self):
        """Test validation of valid configuration"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "validate_config",
                "arguments": {
                    "config": {
                        "loader": 16,
                        "shellcode_type": "donut",
                        "encoding": "uuid",
                        "compiler": "mingw"
                    }
                }
            }
        }
        response = self.server.handle_request(request)

        text = response["result"]["content"][0]["text"]
        result = json.loads(text)
        assert result["valid"] is True
        assert isinstance(result["errors"], list)
        assert isinstance(result["warnings"], list)

    def test_validate_config_invalid_loader(self):
        """Test validation detects invalid loader"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "validate_config",
                "arguments": {
                    "config": {
                        "loader": 999,
                        "shellcode_type": "donut"
                    }
                }
            }
        }
        response = self.server.handle_request(request)

        text = response["result"]["content"][0]["text"]
        result = json.loads(text)
        assert result["valid"] is False
        assert len(result["errors"]) > 0

    def test_validate_config_missing_required(self):
        """Test validation detects missing required fields"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "validate_config",
                "arguments": {
                    "config": {
                        "encoding": "uuid"
                    }
                }
            }
        }
        response = self.server.handle_request(request)

        text = response["result"]["content"][0]["text"]
        result = json.loads(text)
        assert result["valid"] is False
        assert len(result["errors"]) >= 2  # Missing loader and shellcode_type

    def test_validate_config_provides_warnings(self):
        """Test validation provides warnings"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "validate_config",
                "arguments": {
                    "config": {
                        "loader": 16,
                        "shellcode_type": "donut",
                        "obfuscate": False,
                        "anti_emulation": False
                    }
                }
            }
        }
        response = self.server.handle_request(request)

        text = response["result"]["content"][0]["text"]
        result = json.loads(text)
        # Should warn about disabled security features
        assert len(result["warnings"]) > 0

    def test_validate_config_empty_config(self):
        """Test validation of empty configuration"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "validate_config",
                "arguments": {
                    "config": {}
                }
            }
        }
        response = self.server.handle_request(request)

        text = response["result"]["content"][0]["text"]
        result = json.loads(text)
        assert result["valid"] is False
        assert len(result["errors"]) >= 2


class TestToolDiscovery:
    """Test tool discovery and metadata"""

    def setup_method(self):
        self.server = MCPServer()

    def test_all_tools_discoverable(self):
        """Test all tools are discoverable via tools/list"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }
        response = self.server.handle_request(request)

        tool_names = [tool["name"] for tool in response["result"]["tools"]]
        expected_tools = [
            "generate_loader",
            "list_loaders",
            "list_encodings",
            "list_shellcode_types",
            "validate_config"
        ]

        for expected in expected_tools:
            assert expected in tool_names

    def test_all_tools_have_descriptions(self):
        """Test all tools have non-empty descriptions"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }
        response = self.server.handle_request(request)

        for tool in response["result"]["tools"]:
            assert "description" in tool
            assert len(tool["description"]) > 0
            assert isinstance(tool["description"], str)

    def test_all_tools_have_input_schemas(self):
        """Test all tools have valid input schemas"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }
        response = self.server.handle_request(request)

        for tool in response["result"]["tools"]:
            assert "inputSchema" in tool
            assert "type" in tool["inputSchema"]
            assert tool["inputSchema"]["type"] == "object"
            assert "properties" in tool["inputSchema"]

    def test_generate_loader_schema_completeness(self):
        """Test generate_loader has complete schema"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }
        response = self.server.handle_request(request)

        generate_loader = next(
            tool for tool in response["result"]["tools"]
            if tool["name"] == "generate_loader"
        )

        schema = generate_loader["inputSchema"]
        assert "input_file" in schema["properties"]
        assert "output_file" in schema["properties"]
        assert "loader" in schema["properties"]
        assert "shellcode_type" in schema["properties"]
        assert "required" in schema
        assert "input_file" in schema["required"]


class TestToolInteroperability:
    """Test tools working together"""

    def setup_method(self):
        self.server = MCPServer()

    def test_list_then_validate_workflow(self):
        """Test listing options then validating config"""
        # First list available options
        list_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "list_encodings",
                "arguments": {}
            }
        }
        list_response = self.server.handle_request(list_request)
        assert "result" in list_response

        # Then validate a config using one of those options
        validate_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "validate_config",
                "arguments": {
                    "config": {
                        "loader": 16,
                        "shellcode_type": "donut",
                        "encoding": "uuid"
                    }
                }
            }
        }
        validate_response = self.server.handle_request(validate_request)
        assert "result" in validate_response

    def test_validate_then_generate_workflow(self):
        """Test validating config then generating loader"""
        # First validate
        validate_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "validate_config",
                "arguments": {
                    "config": {
                        "loader": 16,
                        "shellcode_type": "donut"
                    }
                }
            }
        }
        validate_response = self.server.handle_request(validate_request)

        text = validate_response["result"]["content"][0]["text"]
        result = json.loads(text)

        if result["valid"]:
            # Then generate
            generate_request = {
                "jsonrpc": "2.0",
                "id": 2,
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
            generate_response = self.server.handle_request(generate_request)
            assert "result" in generate_response


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
