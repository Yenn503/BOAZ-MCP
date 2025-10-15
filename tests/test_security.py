"""
Test Security Features
Tests path traversal prevention, command injection prevention, and input validation
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from boaz_mcp_server import MCPServer, ERROR_INVALID_PARAMS


class TestPathTraversalPrevention:
    """Test prevention of path traversal attacks"""

    def setup_method(self):
        self.server = MCPServer()

    def test_reject_parent_directory_traversal(self):
        """Test rejection of ../ in paths"""
        assert not self.server._validate_path("../etc/passwd")
        assert not self.server._validate_path("../../sensitive/file")
        assert not self.server._validate_path("safe/../../../etc/passwd")

    def test_reject_absolute_paths(self):
        """Test rejection of absolute paths"""
        assert not self.server._validate_path("/etc/passwd")
        assert not self.server._validate_path("/var/log/sensitive.log")
        assert not self.server._validate_path("/root/.ssh/id_rsa")

    def test_accept_safe_relative_paths(self):
        """Test acceptance of safe relative paths"""
        assert self.server._validate_path("output/file.exe")
        assert self.server._validate_path("test.bin")
        assert self.server._validate_path("subdir/file.exe")

    def test_generate_loader_rejects_path_traversal_input(self):
        """Test generate_loader rejects path traversal in input_file"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "generate_loader",
                "arguments": {
                    "input_file": "../../../etc/passwd",
                    "output_file": "output.exe",
                    "loader": 16,
                    "shellcode_type": "donut"
                }
            }
        }
        response = self.server.handle_request(request)

        assert "error" in response
        assert response["error"]["code"] == ERROR_INVALID_PARAMS
        assert "path traversal" in response["error"]["message"].lower()

    def test_generate_loader_rejects_path_traversal_output(self):
        """Test generate_loader rejects path traversal in output_file"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "generate_loader",
                "arguments": {
                    "input_file": "input.exe",
                    "output_file": "../../../tmp/malicious.exe",
                    "loader": 16,
                    "shellcode_type": "donut"
                }
            }
        }
        response = self.server.handle_request(request)

        assert "error" in response
        assert response["error"]["code"] == ERROR_INVALID_PARAMS
        assert "path traversal" in response["error"]["message"].lower()

    def test_generate_loader_rejects_absolute_paths(self):
        """Test generate_loader rejects absolute paths"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "generate_loader",
                "arguments": {
                    "input_file": "/etc/passwd",
                    "output_file": "output.exe",
                    "loader": 16,
                    "shellcode_type": "donut"
                }
            }
        }
        response = self.server.handle_request(request)

        assert "error" in response
        assert response["error"]["code"] == ERROR_INVALID_PARAMS

    def test_validate_config_checks_path_traversal(self):
        """Test validate_config detects path traversal"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "validate_config",
                "arguments": {
                    "config": {
                        "input_file": "../../../etc/passwd",
                        "output_file": "output.exe",
                        "loader": 16,
                        "shellcode_type": "donut"
                    }
                }
            }
        }
        response = self.server.handle_request(request)

        assert "result" in response
        content = response["result"]["content"][0]["text"]
        result = eval(content)  # Parse JSON from text

        assert result["valid"] is False
        assert any("path traversal" in err.lower() for err in result["errors"])


class TestCommandInjectionPrevention:
    """Test prevention of command injection attacks"""

    def setup_method(self):
        self.server = MCPServer()

    def test_sanitize_removes_semicolons(self):
        """Test sanitization removes semicolons"""
        result = self.server._sanitize_input("file.exe; rm -rf /")
        assert ";" not in result

    def test_sanitize_removes_pipes(self):
        """Test sanitization removes pipes"""
        result = self.server._sanitize_input("file.exe | cat /etc/passwd")
        assert "|" not in result

    def test_sanitize_removes_ampersands(self):
        """Test sanitization removes ampersands"""
        result = self.server._sanitize_input("file.exe && malicious")
        assert "&" not in result

    def test_sanitize_removes_backticks(self):
        """Test sanitization removes backticks"""
        result = self.server._sanitize_input("file.exe `whoami`")
        assert "`" not in result

    def test_sanitize_removes_dollar_signs(self):
        """Test sanitization removes dollar signs"""
        result = self.server._sanitize_input("file.exe $(whoami)")
        assert "$" not in result

    def test_sanitize_removes_parentheses(self):
        """Test sanitization removes parentheses"""
        result = self.server._sanitize_input("file.exe $(command)")
        assert "(" not in result
        assert ")" not in result

    def test_sanitize_removes_redirections(self):
        """Test sanitization removes redirection operators"""
        result = self.server._sanitize_input("file.exe > /tmp/output")
        assert ">" not in result
        result = self.server._sanitize_input("file.exe < /tmp/input")
        assert "<" not in result

    def test_sanitize_removes_newlines(self):
        """Test sanitization removes newlines"""
        result = self.server._sanitize_input("file.exe\nrm -rf /")
        assert "\n" not in result
        assert "\r" not in result

    def test_sanitize_preserves_safe_characters(self):
        """Test sanitization preserves safe file paths"""
        safe_input = "test_file.exe"
        result = self.server._sanitize_input(safe_input)
        assert result == safe_input

    def test_sanitize_handles_multiple_dangerous_chars(self):
        """Test sanitization handles multiple dangerous characters"""
        dangerous = "file.exe; cat /etc/passwd | grep root && echo 'pwned'"
        result = self.server._sanitize_input(dangerous)
        assert ";" not in result
        assert "|" not in result
        assert "&" not in result


class TestInputValidation:
    """Test input validation for all parameters"""

    def setup_method(self):
        self.server = MCPServer()

    def test_validate_loader_number_accepts_valid(self):
        """Test validation accepts valid loader numbers"""
        valid_loaders = [1, 2, 3, 16, 20, 48, 73, 77]
        for loader in valid_loaders:
            assert self.server._validate_loader_number(loader)

    def test_validate_loader_number_rejects_invalid(self):
        """Test validation rejects invalid loader numbers"""
        invalid_loaders = [0, -1, 13, 21, 99, 100, 999]
        for loader in invalid_loaders:
            assert not self.server._validate_loader_number(loader)

    def test_validate_encoding_accepts_valid(self):
        """Test validation accepts valid encodings"""
        valid_encodings = ['uuid', 'xor', 'mac', 'ipv4', 'base45', 'base64',
                          'base58', 'aes', 'aes2', 'des', 'chacha', 'rc4']
        for encoding in valid_encodings:
            assert self.server._validate_encoding(encoding)

    def test_validate_encoding_rejects_invalid(self):
        """Test validation rejects invalid encodings"""
        invalid_encodings = ['invalid', 'md5', 'sha256', '', 'INVALID']
        for encoding in invalid_encodings:
            assert not self.server._validate_encoding(encoding)

    def test_validate_shellcode_type_accepts_valid(self):
        """Test validation accepts valid shellcode types"""
        valid_types = ['donut', 'pe2sh', 'rc4', 'amber', 'shoggoth']
        for stype in valid_types:
            assert self.server._validate_shellcode_type(stype)

    def test_validate_shellcode_type_rejects_invalid(self):
        """Test validation rejects invalid shellcode types"""
        invalid_types = ['invalid', 'msfvenom', '', 'DONUT']
        for stype in invalid_types:
            assert not self.server._validate_shellcode_type(stype)

    def test_validate_compiler_accepts_valid(self):
        """Test validation accepts valid compilers"""
        valid_compilers = ['mingw', 'pluto', 'akira']
        for compiler in valid_compilers:
            assert self.server._validate_compiler(compiler)

    def test_validate_compiler_rejects_invalid(self):
        """Test validation rejects invalid compilers"""
        invalid_compilers = ['gcc', 'clang', 'msvc', '', 'MINGW']
        for compiler in invalid_compilers:
            assert not self.server._validate_compiler(compiler)

    def test_generate_loader_validates_loader_number(self):
        """Test generate_loader validates loader number"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "generate_loader",
                "arguments": {
                    "input_file": "input.exe",
                    "output_file": "output.exe",
                    "loader": 999,  # Invalid
                    "shellcode_type": "donut"
                }
            }
        }
        response = self.server.handle_request(request)

        assert "error" in response
        assert "Invalid loader number" in response["error"]["message"]

    def test_generate_loader_validates_encoding(self):
        """Test generate_loader validates encoding"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "generate_loader",
                "arguments": {
                    "input_file": "input.exe",
                    "output_file": "output.exe",
                    "loader": 16,
                    "shellcode_type": "donut",
                    "encoding": "invalid_encoding"
                }
            }
        }
        response = self.server.handle_request(request)

        assert "error" in response
        assert "Invalid encoding" in response["error"]["message"]

    def test_generate_loader_validates_shellcode_type(self):
        """Test generate_loader validates shellcode type"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "generate_loader",
                "arguments": {
                    "input_file": "input.exe",
                    "output_file": "output.exe",
                    "loader": 16,
                    "shellcode_type": "invalid_type"
                }
            }
        }
        response = self.server.handle_request(request)

        assert "error" in response
        assert "Invalid shellcode type" in response["error"]["message"]

    def test_generate_loader_validates_compiler(self):
        """Test generate_loader validates compiler"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "generate_loader",
                "arguments": {
                    "input_file": "input.exe",
                    "output_file": "output.exe",
                    "loader": 16,
                    "shellcode_type": "donut",
                    "compiler": "invalid_compiler"
                }
            }
        }
        response = self.server.handle_request(request)

        assert "error" in response
        assert "Invalid compiler" in response["error"]["message"]


class TestRequiredParameters:
    """Test that required parameters are enforced"""

    def setup_method(self):
        self.server = MCPServer()

    def test_generate_loader_requires_input_file(self):
        """Test generate_loader requires input_file"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "generate_loader",
                "arguments": {
                    "output_file": "output.exe",
                    "loader": 16,
                    "shellcode_type": "donut"
                }
            }
        }
        response = self.server.handle_request(request)

        assert "error" in response
        assert "input_file" in response["error"]["message"]

    def test_generate_loader_requires_output_file(self):
        """Test generate_loader requires output_file"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "generate_loader",
                "arguments": {
                    "input_file": "input.exe",
                    "loader": 16,
                    "shellcode_type": "donut"
                }
            }
        }
        response = self.server.handle_request(request)

        assert "error" in response
        assert "output_file" in response["error"]["message"]

    def test_generate_loader_requires_loader(self):
        """Test generate_loader requires loader number"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "generate_loader",
                "arguments": {
                    "input_file": "input.exe",
                    "output_file": "output.exe",
                    "shellcode_type": "donut"
                }
            }
        }
        response = self.server.handle_request(request)

        assert "error" in response
        assert "loader" in response["error"]["message"]

    def test_generate_loader_requires_shellcode_type(self):
        """Test generate_loader requires shellcode_type"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "generate_loader",
                "arguments": {
                    "input_file": "input.exe",
                    "output_file": "output.exe",
                    "loader": 16
                }
            }
        }
        response = self.server.handle_request(request)

        assert "error" in response
        assert "shellcode_type" in response["error"]["message"]


class TestCaseSensitivity:
    """Test that validation is case-sensitive for security"""

    def setup_method(self):
        self.server = MCPServer()

    def test_encoding_validation_case_sensitive(self):
        """Test encoding validation is case-sensitive"""
        assert not self.server._validate_encoding("UUID")
        assert not self.server._validate_encoding("XOR")
        assert not self.server._validate_encoding("AES")
        assert self.server._validate_encoding("uuid")
        assert self.server._validate_encoding("xor")
        assert self.server._validate_encoding("aes")

    def test_shellcode_type_validation_case_sensitive(self):
        """Test shellcode type validation is case-sensitive"""
        assert not self.server._validate_shellcode_type("DONUT")
        assert not self.server._validate_shellcode_type("Donut")
        assert self.server._validate_shellcode_type("donut")

    def test_compiler_validation_case_sensitive(self):
        """Test compiler validation is case-sensitive"""
        assert not self.server._validate_compiler("MINGW")
        assert not self.server._validate_compiler("Mingw")
        assert self.server._validate_compiler("mingw")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
