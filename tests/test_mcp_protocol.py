"""
Test MCP Protocol Compliance
Tests JSON-RPC 2.0 compliance, protocol version, and basic MCP operations
"""

import pytest
import json
import sys
from pathlib import Path

# Add parent directory to path to import the server
sys.path.insert(0, str(Path(__file__).parent.parent))

from boaz_mcp_server import MCPServer, JSONRPC_VERSION, PROTOCOL_VERSION
from boaz_mcp_server import (
    ERROR_PARSE_ERROR,
    ERROR_INVALID_REQUEST,
    ERROR_METHOD_NOT_FOUND,
    ERROR_INVALID_PARAMS,
    ERROR_INTERNAL_ERROR
)


class TestJSONRPCCompliance:
    """Test JSON-RPC 2.0 specification compliance"""

    def setup_method(self):
        """Setup test server instance"""
        self.server = MCPServer()

    def test_jsonrpc_version_field(self):
        """Test that responses include correct jsonrpc version"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }
        response = self.server.handle_request(request)

        assert "jsonrpc" in response
        assert response["jsonrpc"] == "2.0"

    def test_success_response_structure(self):
        """Test success response has correct structure"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }
        response = self.server.handle_request(request)

        assert "jsonrpc" in response
        assert "id" in response
        assert "result" in response
        assert "error" not in response
        assert response["id"] == 1

    def test_error_response_structure(self):
        """Test error response has correct structure"""
        request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "nonexistent_method",
            "params": {}
        }
        response = self.server.handle_request(request)

        assert "jsonrpc" in response
        assert "id" in response
        assert "error" in response
        assert "result" not in response
        assert response["id"] == 2

    def test_error_object_structure(self):
        """Test error object contains required fields"""
        request = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "invalid_method"
        }
        response = self.server.handle_request(request)

        error = response["error"]
        assert "code" in error
        assert "message" in error
        assert isinstance(error["code"], int)
        assert isinstance(error["message"], str)

    def test_invalid_jsonrpc_version(self):
        """Test rejection of invalid JSON-RPC version"""
        request = {
            "jsonrpc": "1.0",
            "id": 4,
            "method": "initialize"
        }
        response = self.server.handle_request(request)

        assert "error" in response
        assert response["error"]["code"] == ERROR_INVALID_REQUEST

    def test_missing_jsonrpc_field(self):
        """Test handling of missing jsonrpc field"""
        request = {
            "id": 5,
            "method": "initialize"
        }
        response = self.server.handle_request(request)

        assert "error" in response
        assert response["error"]["code"] == ERROR_INVALID_REQUEST

    def test_method_not_found_error_code(self):
        """Test correct error code for unknown methods"""
        request = {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "unknown_method"
        }
        response = self.server.handle_request(request)

        assert response["error"]["code"] == ERROR_METHOD_NOT_FOUND

    def test_invalid_params_error_code(self):
        """Test correct error code for invalid parameters"""
        request = {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "generate_loader",
                "arguments": {}  # Missing required parameters
            }
        }
        response = self.server.handle_request(request)

        assert response["error"]["code"] == ERROR_INVALID_PARAMS

    def test_id_preservation(self):
        """Test that request ID is preserved in response"""
        test_ids = [1, "string-id", None, 12345]

        for test_id in test_ids:
            request = {
                "jsonrpc": "2.0",
                "id": test_id,
                "method": "initialize",
                "params": {}
            }
            response = self.server.handle_request(request)
            assert response["id"] == test_id


class TestMCPInitialization:
    """Test MCP initialization protocol"""

    def setup_method(self):
        self.server = MCPServer()

    def test_initialize_method_exists(self):
        """Test initialize method is implemented"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }
        response = self.server.handle_request(request)

        assert "result" in response
        assert "error" not in response

    def test_initialize_returns_protocol_version(self):
        """Test initialize returns protocol version"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }
        response = self.server.handle_request(request)

        assert "protocolVersion" in response["result"]
        assert response["result"]["protocolVersion"] == PROTOCOL_VERSION

    def test_initialize_returns_capabilities(self):
        """Test initialize returns server capabilities"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }
        response = self.server.handle_request(request)

        assert "capabilities" in response["result"]
        assert "tools" in response["result"]["capabilities"]

    def test_initialize_returns_server_info(self):
        """Test initialize returns server information"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }
        response = self.server.handle_request(request)

        assert "serverInfo" in response["result"]
        assert "name" in response["result"]["serverInfo"]
        assert "version" in response["result"]["serverInfo"]

    def test_server_name(self):
        """Test server reports correct name"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }
        response = self.server.handle_request(request)

        assert response["result"]["serverInfo"]["name"] == "boaz-mcp-server"


class TestToolsList:
    """Test tools/list method"""

    def setup_method(self):
        self.server = MCPServer()

    def test_tools_list_method_exists(self):
        """Test tools/list method is implemented"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }
        response = self.server.handle_request(request)

        assert "result" in response
        assert "error" not in response

    def test_tools_list_returns_tools_array(self):
        """Test tools/list returns array of tools"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }
        response = self.server.handle_request(request)

        assert "tools" in response["result"]
        assert isinstance(response["result"]["tools"], list)
        assert len(response["result"]["tools"]) > 0

    def test_tool_structure(self):
        """Test each tool has required fields"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }
        response = self.server.handle_request(request)

        for tool in response["result"]["tools"]:
            assert "name" in tool
            assert "description" in tool
            assert "inputSchema" in tool
            assert isinstance(tool["name"], str)
            assert isinstance(tool["description"], str)
            assert isinstance(tool["inputSchema"], dict)

    def test_generate_loader_tool_exists(self):
        """Test generate_loader tool is listed"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }
        response = self.server.handle_request(request)

        tool_names = [tool["name"] for tool in response["result"]["tools"]]
        assert "generate_loader" in tool_names

    def test_list_loaders_tool_exists(self):
        """Test list_loaders tool is listed"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }
        response = self.server.handle_request(request)

        tool_names = [tool["name"] for tool in response["result"]["tools"]]
        assert "list_loaders" in tool_names

    def test_tool_input_schema_valid(self):
        """Test tool input schemas are valid JSON Schema"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }
        response = self.server.handle_request(request)

        for tool in response["result"]["tools"]:
            schema = tool["inputSchema"]
            assert "type" in schema
            assert schema["type"] == "object"
            assert "properties" in schema


class TestToolsCall:
    """Test tools/call method"""

    def setup_method(self):
        self.server = MCPServer()

    def test_tools_call_method_exists(self):
        """Test tools/call method is implemented"""
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

    def test_tools_call_unknown_tool(self):
        """Test calling unknown tool returns error"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "nonexistent_tool",
                "arguments": {}
            }
        }
        response = self.server.handle_request(request)

        assert "error" in response
        assert response["error"]["code"] == ERROR_INTERNAL_ERROR

    def test_tools_call_missing_name(self):
        """Test tools/call without tool name"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "arguments": {}
            }
        }
        response = self.server.handle_request(request)

        assert "error" in response

    def test_tools_call_response_structure(self):
        """Test tools/call response has correct structure"""
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
        assert "content" in response["result"]
        assert isinstance(response["result"]["content"], list)

    def test_content_array_structure(self):
        """Test content array items have correct structure"""
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

        for content_item in response["result"]["content"]:
            assert "type" in content_item
            assert "text" in content_item
            assert content_item["type"] == "text"


class TestErrorHandling:
    """Test error handling scenarios"""

    def setup_method(self):
        self.server = MCPServer()

    def test_malformed_json_handling(self):
        """Test handling of malformed JSON is graceful"""
        # This test would be for the run() method
        # For unit testing, we test the error creation
        error = self.server._create_error_response(
            None,
            ERROR_PARSE_ERROR,
            "Parse error"
        )

        assert error["error"]["code"] == ERROR_PARSE_ERROR

    def test_error_with_data_field(self):
        """Test error responses can include data field"""
        error_data = {"detail": "Additional error information"}
        error = self.server._create_error_response(
            1,
            ERROR_INTERNAL_ERROR,
            "Internal error",
            error_data
        )

        assert "data" in error["error"]
        assert error["error"]["data"] == error_data

    def test_error_without_data_field(self):
        """Test error responses without data field"""
        error = self.server._create_error_response(
            1,
            ERROR_INTERNAL_ERROR,
            "Internal error"
        )

        assert "data" not in error["error"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
