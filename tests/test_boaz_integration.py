"""
Test BOAZ Integration
Tests BOAZ command generation, parameter handling, and integration with BOAZ tool
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from boaz_mcp_server import MCPServer


class TestCommandGeneration:
    """Test BOAZ command generation"""

    def setup_method(self):
        self.server = MCPServer()

    def test_basic_command_generation(self):
        """Test basic BOAZ command is generated correctly"""
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
                    "shellcode_type": "donut"
                }
            }
        }
        response = self.server.handle_request(request)

        assert "result" in response
        content = response["result"]["content"][0]["text"]
        assert "python3" in content
        assert "Boaz.py" in content
        assert "-f input.exe" in content
        assert "-o output.exe" in content
        assert "-l 16" in content
        assert "-t donut" in content

    def test_command_with_encoding(self):
        """Test command generation with encoding parameter"""
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
                    "encoding": "uuid"
                }
            }
        }
        response = self.server.handle_request(request)

        content = response["result"]["content"][0]["text"]
        assert "-e uuid" in content

    def test_command_with_compiler(self):
        """Test command generation with compiler parameter"""
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
                    "compiler": "akira"
                }
            }
        }
        response = self.server.handle_request(request)

        content = response["result"]["content"][0]["text"]
        assert "-c akira" in content

    def test_command_with_obfuscate_flag(self):
        """Test command generation with obfuscate flag"""
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
                    "obfuscate": True
                }
            }
        }
        response = self.server.handle_request(request)

        content = response["result"]["content"][0]["text"]
        assert "-obf" in content

    def test_command_with_anti_emulation_flag(self):
        """Test command generation with anti-emulation flag"""
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
                    "anti_emulation": True
                }
            }
        }
        response = self.server.handle_request(request)

        content = response["result"]["content"][0]["text"]
        assert "-a" in content

    def test_command_with_etw_patching_flag(self):
        """Test command generation with ETW patching flag"""
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
                    "etw_patching": True
                }
            }
        }
        response = self.server.handle_request(request)

        content = response["result"]["content"][0]["text"]
        assert "-etw" in content

    def test_command_with_multiple_flags(self):
        """Test command generation with multiple flags"""
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
                    "encoding": "aes",
                    "compiler": "pluto",
                    "obfuscate": True,
                    "anti_emulation": True,
                    "etw_patching": True
                }
            }
        }
        response = self.server.handle_request(request)

        content = response["result"]["content"][0]["text"]
        assert "-e aes" in content
        assert "-c pluto" in content
        assert "-obf" in content
        assert "-a" in content
        assert "-etw" in content

    def test_command_false_flags_not_included(self):
        """Test that false boolean flags are not included in command"""
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
                    "obfuscate": False,
                    "anti_emulation": False,
                    "etw_patching": False
                }
            }
        }
        response = self.server.handle_request(request)

        content = response["result"]["content"][0]["text"]
        # Should not contain the flags
        assert content.count("-obf") == 0 or "-obf" not in content.split("Command prepared:")[1].split("\n")[0]
        assert content.count("-a") == 0 or "-a" not in content.split("Command prepared:")[1].split("\n")[0]
        assert content.count("-etw") == 0 or "-etw" not in content.split("Command prepared:")[1].split("\n")[0]


class TestLoaderSupport:
    """Test support for different loader types"""

    def setup_method(self):
        self.server = MCPServer()

    def test_loader_1_supported(self):
        """Test loader 1 (Proxy syscall) is supported"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "generate_loader",
                "arguments": {
                    "input_file": "input.exe",
                    "output_file": "output.exe",
                    "loader": 1,
                    "shellcode_type": "donut"
                }
            }
        }
        response = self.server.handle_request(request)
        assert "result" in response

    def test_loader_16_supported(self):
        """Test loader 16 (Classic userland) is supported"""
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
                    "shellcode_type": "donut"
                }
            }
        }
        response = self.server.handle_request(request)
        assert "result" in response

    def test_loader_48_supported(self):
        """Test loader 48 (Sifu breakpoint handler) is supported"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "generate_loader",
                "arguments": {
                    "input_file": "input.exe",
                    "output_file": "output.exe",
                    "loader": 48,
                    "shellcode_type": "donut"
                }
            }
        }
        response = self.server.handle_request(request)
        assert "result" in response

    def test_loader_73_supported(self):
        """Test loader 73 (VT Pointer threadless) is supported"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "generate_loader",
                "arguments": {
                    "input_file": "input.exe",
                    "output_file": "output.exe",
                    "loader": 73,
                    "shellcode_type": "donut"
                }
            }
        }
        response = self.server.handle_request(request)
        assert "result" in response

    def test_invalid_loader_rejected(self):
        """Test invalid loader numbers are rejected"""
        invalid_loaders = [0, 13, 21, 99, 100]
        for loader in invalid_loaders:
            request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "generate_loader",
                    "arguments": {
                        "input_file": "input.exe",
                        "output_file": "output.exe",
                        "loader": loader,
                        "shellcode_type": "donut"
                    }
                }
            }
            response = self.server.handle_request(request)
            assert "error" in response


class TestShellcodeTypeSupport:
    """Test support for different shellcode types"""

    def setup_method(self):
        self.server = MCPServer()

    def test_donut_shellcode_type(self):
        """Test donut shellcode type"""
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
                    "shellcode_type": "donut"
                }
            }
        }
        response = self.server.handle_request(request)
        assert "result" in response
        content = response["result"]["content"][0]["text"]
        assert "-t donut" in content

    def test_pe2sh_shellcode_type(self):
        """Test pe2sh shellcode type"""
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
                    "shellcode_type": "pe2sh"
                }
            }
        }
        response = self.server.handle_request(request)
        assert "result" in response
        content = response["result"]["content"][0]["text"]
        assert "-t pe2sh" in content

    def test_amber_shellcode_type(self):
        """Test amber shellcode type"""
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
                    "shellcode_type": "amber"
                }
            }
        }
        response = self.server.handle_request(request)
        assert "result" in response
        content = response["result"]["content"][0]["text"]
        assert "-t amber" in content

    def test_shoggoth_shellcode_type(self):
        """Test shoggoth shellcode type"""
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
                    "shellcode_type": "shoggoth"
                }
            }
        }
        response = self.server.handle_request(request)
        assert "result" in response
        content = response["result"]["content"][0]["text"]
        assert "-t shoggoth" in content


class TestEncodingSupport:
    """Test support for different encoding types"""

    def setup_method(self):
        self.server = MCPServer()

    def test_uuid_encoding(self):
        """Test UUID encoding"""
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
                    "encoding": "uuid"
                }
            }
        }
        response = self.server.handle_request(request)
        assert "result" in response
        content = response["result"]["content"][0]["text"]
        assert "-e uuid" in content

    def test_aes_encoding(self):
        """Test AES encoding"""
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
                    "encoding": "aes"
                }
            }
        }
        response = self.server.handle_request(request)
        assert "result" in response
        content = response["result"]["content"][0]["text"]
        assert "-e aes" in content

    def test_xor_encoding(self):
        """Test XOR encoding"""
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
                    "encoding": "xor"
                }
            }
        }
        response = self.server.handle_request(request)
        assert "result" in response
        content = response["result"]["content"][0]["text"]
        assert "-e xor" in content

    def test_rc4_encoding(self):
        """Test RC4 encoding"""
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
                    "encoding": "rc4"
                }
            }
        }
        response = self.server.handle_request(request)
        assert "result" in response
        content = response["result"]["content"][0]["text"]
        assert "-e rc4" in content

    def test_base45_encoding(self):
        """Test Base45 encoding"""
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
                    "encoding": "base45"
                }
            }
        }
        response = self.server.handle_request(request)
        assert "result" in response
        content = response["result"]["content"][0]["text"]
        assert "-e base45" in content

    def test_base64_encoding(self):
        """Test Base64 encoding"""
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
                    "encoding": "base64"
                }
            }
        }
        response = self.server.handle_request(request)
        assert "result" in response
        content = response["result"]["content"][0]["text"]
        assert "-e base64" in content

    def test_base58_encoding(self):
        """Test Base58 encoding"""
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
                    "encoding": "base58"
                }
            }
        }
        response = self.server.handle_request(request)
        assert "result" in response
        content = response["result"]["content"][0]["text"]
        assert "-e base58" in content

    def test_aes2_encoding(self):
        """Test AES2 encoding"""
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
                    "encoding": "aes2"
                }
            }
        }
        response = self.server.handle_request(request)
        assert "result" in response
        content = response["result"]["content"][0]["text"]
        assert "-e aes2" in content


class TestCompilerSupport:
    """Test support for different compilers"""

    def setup_method(self):
        self.server = MCPServer()

    def test_mingw_compiler(self):
        """Test MingW compiler"""
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
                    "compiler": "mingw"
                }
            }
        }
        response = self.server.handle_request(request)
        assert "result" in response
        content = response["result"]["content"][0]["text"]
        assert "-c mingw" in content

    def test_pluto_compiler(self):
        """Test Pluto compiler"""
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
                    "compiler": "pluto"
                }
            }
        }
        response = self.server.handle_request(request)
        assert "result" in response
        content = response["result"]["content"][0]["text"]
        assert "-c pluto" in content

    def test_akira_compiler(self):
        """Test Akira compiler"""
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
                    "compiler": "akira"
                }
            }
        }
        response = self.server.handle_request(request)
        assert "result" in response
        content = response["result"]["content"][0]["text"]
        assert "-c akira" in content


class TestConfigurationValidation:
    """Test configuration validation functionality"""

    def setup_method(self):
        self.server = MCPServer()

    def test_validate_valid_config(self):
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
                        "compiler": "akira"
                    }
                }
            }
        }
        response = self.server.handle_request(request)

        assert "result" in response
        content = response["result"]["content"][0]["text"]
        result = eval(content)
        assert result["valid"] is True
        assert len(result["errors"]) == 0

    def test_validate_invalid_loader(self):
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

        content = response["result"]["content"][0]["text"]
        result = eval(content)
        assert result["valid"] is False
        assert any("loader" in err.lower() for err in result["errors"])

    def test_validate_missing_required_fields(self):
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

        content = response["result"]["content"][0]["text"]
        result = eval(content)
        assert result["valid"] is False
        assert len(result["errors"]) > 0

    def test_validate_provides_warnings(self):
        """Test validation provides best practice warnings"""
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

        content = response["result"]["content"][0]["text"]
        result = eval(content)
        # Should warn about missing obfuscation or anti-emulation
        assert len(result["warnings"]) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
