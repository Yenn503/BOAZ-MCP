#!/usr/bin/env python3
"""
BOAZ MCP Server - Model Context Protocol server for BOAZ evasion tool
Provides tools for generating loaders, managing shellcode, and configuring evasion techniques
"""

import json
import sys
import os
import subprocess
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

# MCP Protocol Constants
JSONRPC_VERSION = "2.0"
PROTOCOL_VERSION = "2024-11-05"

# Error codes following JSON-RPC 2.0 specification
ERROR_PARSE_ERROR = -32700
ERROR_INVALID_REQUEST = -32600
ERROR_METHOD_NOT_FOUND = -32601
ERROR_INVALID_PARAMS = -32602
ERROR_INTERNAL_ERROR = -32603

# BOAZ base directory
BOAZ_BASE_DIR = Path(__file__).parent / "BOAZ_beta"


class MCPServer:
    """MCP Server for BOAZ evasion tool"""

    def __init__(self):
        self.capabilities = {
            "tools": {}
        }

    def _create_error_response(self, request_id: Any, code: int, message: str, data: Any = None) -> Dict:
        """Create JSON-RPC error response"""
        error = {
            "code": code,
            "message": message
        }
        if data is not None:
            error["data"] = data

        return {
            "jsonrpc": JSONRPC_VERSION,
            "id": request_id,
            "error": error
        }

    def _create_success_response(self, request_id: Any, result: Any) -> Dict:
        """Create JSON-RPC success response"""
        return {
            "jsonrpc": JSONRPC_VERSION,
            "id": request_id,
            "result": result
        }

    def _validate_path(self, path: str) -> bool:
        """Validate path to prevent path traversal attacks"""
        try:
            # Resolve to absolute path
            abs_path = Path(path).resolve()
            # Check for path traversal attempts
            if ".." in str(path) or path.startswith("/"):
                return False
            return True
        except Exception:
            return False

    def _sanitize_input(self, value: str) -> str:
        """Sanitize input to prevent command injection"""
        # Remove potentially dangerous characters
        dangerous_chars = [";", "&", "|", "`", "$", "(", ")", "<", ">", "\n", "\r"]
        sanitized = value
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, "")
        return sanitized

    def _validate_loader_number(self, loader: int) -> bool:
        """Validate loader number is in acceptable range"""
        valid_loaders = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 14, 15, 16, 17, 18, 19, 20,
                        22, 24, 26, 27, 28, 29, 30, 31, 32, 33, 34, 36, 37, 38, 39, 40,
                        41, 48, 49, 51, 52, 54, 56, 57, 58, 59, 60, 61, 63, 65, 66, 67,
                        69, 73, 74, 75, 76, 77]
        return loader in valid_loaders

    def _validate_encoding(self, encoding: str) -> bool:
        """Validate encoding type"""
        valid_encodings = ['uuid', 'xor', 'mac', 'ipv4', 'base45', 'base64', 'base58',
                          'aes', 'des', 'chacha', 'rc4', 'aes2', 'ascon']
        return encoding in valid_encodings

    def _validate_shellcode_type(self, shellcode_type: str) -> bool:
        """Validate shellcode type"""
        valid_types = ['donut', 'pe2sh', 'rc4', 'amber', 'shoggoth']
        return shellcode_type in valid_types

    def _validate_compiler(self, compiler: str) -> bool:
        """Validate compiler choice"""
        valid_compilers = ['mingw', 'pluto', 'akira']
        return compiler in valid_compilers

    def handle_initialize(self, params: Dict) -> Dict:
        """Handle initialize request"""
        return {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "boaz-mcp-server",
                "version": "1.0.0"
            }
        }

    def handle_tools_list(self, params: Dict) -> Dict:
        """Handle tools/list request"""
        return {
            "tools": [
                {
                    "name": "generate_loader",
                    "description": "Generate a BOAZ loader with specified evasion techniques",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "input_file": {
                                "type": "string",
                                "description": "Path to input binary or shellcode file"
                            },
                            "output_file": {
                                "type": "string",
                                "description": "Path for output file"
                            },
                            "loader": {
                                "type": "integer",
                                "description": "Loader template number (1-77)"
                            },
                            "shellcode_type": {
                                "type": "string",
                                "enum": ["donut", "pe2sh", "rc4", "amber", "shoggoth"],
                                "description": "Shellcode generation tool"
                            },
                            "encoding": {
                                "type": "string",
                                "enum": ["uuid", "xor", "mac", "ipv4", "base45", "base64", "base58",
                                        "aes", "des", "chacha", "rc4", "aes2", "ascon"],
                                "description": "Encoding type for shellcode"
                            },
                            "compiler": {
                                "type": "string",
                                "enum": ["mingw", "pluto", "akira"],
                                "description": "Compiler choice"
                            },
                            "obfuscate": {
                                "type": "boolean",
                                "description": "Enable code obfuscation"
                            },
                            "anti_emulation": {
                                "type": "boolean",
                                "description": "Enable anti-emulation checks"
                            },
                            "etw_patching": {
                                "type": "boolean",
                                "description": "Enable ETW patching"
                            }
                        },
                        "required": ["input_file", "output_file", "loader", "shellcode_type"]
                    }
                },
                {
                    "name": "list_loaders",
                    "description": "List all available loader templates",
                    "inputSchema": {
                        "type": "object",
                        "properties": {}
                    }
                },
                {
                    "name": "list_encodings",
                    "description": "List all available encoding methods",
                    "inputSchema": {
                        "type": "object",
                        "properties": {}
                    }
                },
                {
                    "name": "list_shellcode_types",
                    "description": "List all available shellcode generation tools",
                    "inputSchema": {
                        "type": "object",
                        "properties": {}
                    }
                },
                {
                    "name": "validate_config",
                    "description": "Validate a BOAZ configuration before execution",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "config": {
                                "type": "object",
                                "description": "Configuration object to validate"
                            }
                        },
                        "required": ["config"]
                    }
                }
            ]
        }

    def handle_tools_call(self, params: Dict) -> Dict:
        """Handle tools/call request"""
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        if tool_name == "generate_loader":
            return self._generate_loader(arguments)
        elif tool_name == "list_loaders":
            return self._list_loaders()
        elif tool_name == "list_encodings":
            return self._list_encodings()
        elif tool_name == "list_shellcode_types":
            return self._list_shellcode_types()
        elif tool_name == "validate_config":
            return self._validate_config(arguments)
        else:
            raise ValueError(f"Unknown tool: {tool_name}")

    def _generate_loader(self, args: Dict) -> Dict:
        """Generate a BOAZ loader"""
        # Validate required parameters
        if "input_file" not in args:
            raise ValueError("input_file is required")
        if "output_file" not in args:
            raise ValueError("output_file is required")
        if "loader" not in args:
            raise ValueError("loader number is required")
        if "shellcode_type" not in args:
            raise ValueError("shellcode_type is required")

        # Security validation
        if not self._validate_path(args["input_file"]):
            raise ValueError("Invalid input_file path - potential path traversal detected")
        if not self._validate_path(args["output_file"]):
            raise ValueError("Invalid output_file path - potential path traversal detected")

        # Validate parameters
        if not self._validate_loader_number(args["loader"]):
            raise ValueError(f"Invalid loader number: {args['loader']}")
        if not self._validate_shellcode_type(args["shellcode_type"]):
            raise ValueError(f"Invalid shellcode type: {args['shellcode_type']}")

        # Optional parameter validation
        if "encoding" in args and not self._validate_encoding(args["encoding"]):
            raise ValueError(f"Invalid encoding: {args['encoding']}")
        if "compiler" in args and not self._validate_compiler(args["compiler"]):
            raise ValueError(f"Invalid compiler: {args['compiler']}")

        # Build command
        cmd = [
            "python3",
            str(BOAZ_BASE_DIR / "Boaz.py"),
            "-f", args["input_file"],
            "-o", args["output_file"],
            "-l", str(args["loader"]),
            "-t", args["shellcode_type"]
        ]

        # Add optional flags
        if args.get("encoding"):
            cmd.extend(["-e", args["encoding"]])
        if args.get("compiler"):
            cmd.extend(["-c", args["compiler"]])
        if args.get("obfuscate"):
            cmd.append("-obf")
        if args.get("anti_emulation"):
            cmd.append("-a")
        if args.get("etw_patching"):
            cmd.append("-etw")

        # For testing purposes, return the command that would be executed
        # In production, this would actually execute the command
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"Command prepared: {' '.join(cmd)}\n\nNote: This is a test server. In production, this would execute the BOAZ tool."
                }
            ]
        }

    def _list_loaders(self) -> Dict:
        """List all available loaders"""
        loaders = {
            1: "Proxy syscall with custom call stack and threadless execution",
            2: "APC test alert",
            3: "Sifu syscall",
            4: "UUID manual injection",
            5: "Remote mockingJay",
            6: "Local thread hijacking",
            7: "Function pointer invoke local injection",
            8: "Ninja_syscall2",
            9: "RW local mockingJay",
            10: "Ninja syscall 1",
            11: "Sifu Divide and Conquer syscall",
            14: "Exit without executing shellcode",
            15: "Syswhispers2 classic native API calls",
            16: "Classic userland API calls",
            17: "Sifu SysCall with Divide and Conquer",
            18: "Classic userland API calls with WriteProcessMemoryAPC",
            19: "DLL overloading",
            20: "Stealth new Injection (WriteProcessMemoryAPC + DLL overloading)",
        }

        loader_list = "\n".join([f"{num}: {desc}" for num, desc in sorted(loaders.items())])

        return {
            "content": [
                {
                    "type": "text",
                    "text": f"Available BOAZ Loaders:\n\n{loader_list}\n\n(Partial list - see documentation for complete list)"
                }
            ]
        }

    def _list_encodings(self) -> Dict:
        """List all available encodings"""
        encodings = [
            "uuid - Universally Unique Identifier encoding",
            "xor - XOR encoding",
            "mac - MAC address encoding",
            "ipv4 - IPv4 address encoding",
            "base45 - Base45 encoding",
            "base64 - Base64 encoding",
            "base58 - Base58 encoding",
            "aes - AES encryption",
            "des - DES encryption",
            "chacha - ChaCha20 encryption",
            "rc4 - RC4 encryption",
            "aes2 - AES with divide and conquer",
            "ascon - Ascon encryption"
        ]

        return {
            "content": [
                {
                    "type": "text",
                    "text": "Available Encodings:\n\n" + "\n".join(encodings)
                }
            ]
        }

    def _list_shellcode_types(self) -> Dict:
        """List all available shellcode types"""
        types = [
            "donut - The Donut shellcode generator (default)",
            "pe2sh - PE2SH converter",
            "rc4 - RC4 custom encrypted converter",
            "amber - Amber PIC generator",
            "shoggoth - Shoggoth PIC generator"
        ]

        return {
            "content": [
                {
                    "type": "text",
                    "text": "Available Shellcode Types:\n\n" + "\n".join(types)
                }
            ]
        }

    def _validate_config(self, args: Dict) -> Dict:
        """Validate a BOAZ configuration"""
        config = args.get("config", {})
        errors = []
        warnings = []

        # Check required fields
        if "loader" not in config:
            errors.append("Missing required field: loader")
        elif not self._validate_loader_number(config["loader"]):
            errors.append(f"Invalid loader number: {config['loader']}")

        if "shellcode_type" not in config:
            errors.append("Missing required field: shellcode_type")
        elif not self._validate_shellcode_type(config["shellcode_type"]):
            errors.append(f"Invalid shellcode type: {config['shellcode_type']}")

        # Check optional fields
        if "encoding" in config and not self._validate_encoding(config["encoding"]):
            errors.append(f"Invalid encoding: {config['encoding']}")

        if "compiler" in config and not self._validate_compiler(config["compiler"]):
            errors.append(f"Invalid compiler: {config['compiler']}")

        # Security checks
        if "input_file" in config and not self._validate_path(config["input_file"]):
            errors.append("Invalid input_file path - potential path traversal detected")

        if "output_file" in config and not self._validate_path(config["output_file"]):
            errors.append("Invalid output_file path - potential path traversal detected")

        # Warnings for best practices
        if not config.get("obfuscate"):
            warnings.append("Obfuscation is disabled - consider enabling for better evasion")

        if not config.get("anti_emulation"):
            warnings.append("Anti-emulation is disabled - consider enabling for better evasion")

        result = {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings
        }

        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(result, indent=2)
                }
            ]
        }

    def handle_request(self, request: Dict) -> Dict:
        """Main request handler"""
        # Validate JSON-RPC version
        if request.get("jsonrpc") != JSONRPC_VERSION:
            return self._create_error_response(
                request.get("id"),
                ERROR_INVALID_REQUEST,
                f"Invalid JSON-RPC version. Expected {JSONRPC_VERSION}"
            )

        method = request.get("method")
        params = request.get("params", {})
        request_id = request.get("id")

        try:
            if method == "initialize":
                result = self.handle_initialize(params)
            elif method == "tools/list":
                result = self.handle_tools_list(params)
            elif method == "tools/call":
                result = self.handle_tools_call(params)
            else:
                return self._create_error_response(
                    request_id,
                    ERROR_METHOD_NOT_FOUND,
                    f"Method not found: {method}"
                )

            return self._create_success_response(request_id, result)

        except ValueError as e:
            return self._create_error_response(
                request_id,
                ERROR_INVALID_PARAMS,
                str(e)
            )
        except Exception as e:
            return self._create_error_response(
                request_id,
                ERROR_INTERNAL_ERROR,
                f"Internal error: {str(e)}"
            )

    def run(self):
        """Run the MCP server (stdio mode)"""
        for line in sys.stdin:
            try:
                request = json.loads(line)
                response = self.handle_request(request)
                print(json.dumps(response), flush=True)
            except json.JSONDecodeError as e:
                error_response = self._create_error_response(
                    None,
                    ERROR_PARSE_ERROR,
                    f"Parse error: {str(e)}"
                )
                print(json.dumps(error_response), flush=True)


if __name__ == "__main__":
    server = MCPServer()
    server.run()
