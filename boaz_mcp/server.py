#!/usr/bin/env python3
"""
BOAZ MCP Server
Provides MCP interface to BOAZ evasion framework
For authorized red team operations and security research only
"""

import asyncio
import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class BoazMCPServer:
    """MCP server for BOAZ framework integration"""

    # Security constants
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
    SUBPROCESS_TIMEOUT = 300  # 5 minutes

    # Valid parameter values
    VALID_ENCODINGS = ["uuid", "xor", "mac", "ipv4", "base45", "base64",
                       "base58", "aes", "des", "chacha", "rc4", "aes2"]
    VALID_COMPILERS = ["mingw", "pluto", "akira"]
    VALID_SHELLCODE_TYPES = ["donut", "pe2sh", "rc4", "amber", "shoggoth", "augment"]

    def __init__(self):
        self.server = Server("boaz")
        self.boaz_path = os.getenv("BOAZ_PATH")
        if not self.boaz_path:
            raise ValueError("BOAZ_PATH environment variable not set")

        self.boaz_path = os.path.abspath(self.boaz_path)

        self.boaz_script = os.path.join(self.boaz_path, "Boaz.py")
        if not os.path.exists(self.boaz_script):
            raise FileNotFoundError(f"Boaz.py not found at {self.boaz_script}")

        # Register tool handlers
        self.server.list_tools()(self.list_tools)
        self.server.call_tool()(self.call_tool)

        logger.info("BOAZ MCP Server initialized")

    def _validate_path(self, path: str, must_exist: bool = False) -> str:
        """Validate file paths to prevent traversal attacks"""
        logger.debug(f"Validating path: {path}")

        # Reject path traversal patterns
        if ".." in path:
            logger.warning(f"Path traversal detected: {path}")
            raise ValueError("Path traversal not allowed")

        # Reject absolute paths (force relative to BOAZ_PATH)
        if os.path.isabs(path):
            logger.warning(f"Absolute path rejected: {path}")
            raise ValueError("Absolute paths not allowed, use paths relative to BOAZ_PATH")

        # Make path relative to BOAZ_PATH
        safe_path = os.path.join(self.boaz_path, path)
        safe_path = os.path.abspath(safe_path)

        # Ensure it's still within BOAZ_PATH
        if not safe_path.startswith(self.boaz_path):
            logger.warning(f"Path outside BOAZ_PATH: {safe_path}")
            raise ValueError("Path must be within BOAZ_PATH directory")

        if must_exist and not os.path.exists(safe_path):
            logger.error(f"File not found: {safe_path}")
            raise FileNotFoundError(f"File not found: {path}")

        logger.debug(f"Path validated: {safe_path}")
        return safe_path

    def _validate_loader(self, loader: int) -> None:
        """Validate loader number"""
        if not isinstance(loader, int):
            raise ValueError(f"Loader must be an integer, got {type(loader)}")

        if loader < 1 or loader > 77:
            raise ValueError(f"Invalid loader: {loader}. Must be between 1-77")

        logger.debug(f"Loader validated: {loader}")

    def _validate_encoding(self, encoding: str) -> None:
        """Validate encoding type"""
        if encoding not in self.VALID_ENCODINGS:
            raise ValueError(f"Invalid encoding: {encoding}. Valid options: {', '.join(self.VALID_ENCODINGS)}")

        logger.debug(f"Encoding validated: {encoding}")

    def _validate_compiler(self, compiler: str) -> None:
        """Validate compiler choice"""
        if compiler not in self.VALID_COMPILERS:
            raise ValueError(f"Invalid compiler: {compiler}. Valid options: {', '.join(self.VALID_COMPILERS)}")

        logger.debug(f"Compiler validated: {compiler}")

    def _validate_shellcode_type(self, shellcode_type: str) -> None:
        """Validate shellcode type"""
        if shellcode_type not in self.VALID_SHELLCODE_TYPES:
            raise ValueError(f"Invalid shellcode type: {shellcode_type}. Valid options: {', '.join(self.VALID_SHELLCODE_TYPES)}")

        logger.debug(f"Shellcode type validated: {shellcode_type}")

    def _check_file_size(self, path: str) -> None:
        """Check file size is within limits"""
        if not os.path.exists(path):
            return  # Will be caught by other validation

        size = os.path.getsize(path)
        if size > self.MAX_FILE_SIZE:
            logger.error(f"File too large: {size} bytes (max {self.MAX_FILE_SIZE})")
            raise ValueError(f"File too large: {size} bytes (max {self.MAX_FILE_SIZE} bytes / {self.MAX_FILE_SIZE // (1024*1024)}MB)")

        logger.debug(f"File size OK: {size} bytes")

    def _sanitize_string(self, value: str, param_name: str) -> str:
        """Sanitize string inputs to prevent injection"""
        dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '<', '>', '\n', '\r']
        for char in dangerous_chars:
            if char in value:
                logger.warning(f"Dangerous character '{char}' found in {param_name}")
                raise ValueError(f"Invalid character '{char}' in {param_name}")
        return value

    async def list_tools(self) -> list[Tool]:
        """List available BOAZ tools"""
        return [
            Tool(
                name="generate_payload",
                description="Generate evasive payload using BOAZ framework",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "input_file": {
                            "type": "string",
                            "description": "Path to input PE executable"
                        },
                        "output_file": {
                            "type": "string",
                            "description": "Path for output executable"
                        },
                        "loader": {
                            "type": "integer",
                            "description": "Loader number (1-77+)",
                            "default": 16
                        },
                        "encoding": {
                            "type": "string",
                            "enum": ["uuid", "xor", "mac", "ipv4", "base45", "base64",
                                   "base58", "aes", "des", "chacha", "rc4", "aes2"],
                            "description": "Encoding scheme"
                        },
                        "compiler": {
                            "type": "string",
                            "enum": ["mingw", "pluto", "akira"],
                            "default": "mingw",
                            "description": "Compiler choice"
                        },
                        "shellcode_type": {
                            "type": "string",
                            "enum": ["donut", "pe2sh", "rc4", "amber", "shoggoth", "augment"],
                            "default": "donut",
                            "description": "Shellcode generator (use 'augment' for advanced PIC)"
                        },
                        "obfuscate": {
                            "type": "boolean",
                            "description": "Enable source code obfuscation"
                        },
                        "obfuscate_api": {
                            "type": "boolean",
                            "description": "Enable API call obfuscation"
                        },
                        "anti_emulation": {
                            "type": "boolean",
                            "description": "Enable anti-emulation checks"
                        },
                        "sleep": {
                            "type": "boolean",
                            "description": "Enable sleep obfuscation"
                        },
                        "dream": {
                            "type": "integer",
                            "description": "Encrypted stack sleep duration (ms)"
                        },
                        "etw": {
                            "type": "boolean",
                            "description": "Enable ETW patching"
                        },
                        "api_unhooking": {
                            "type": "boolean",
                            "description": "Enable API unhooking"
                        },
                        "god_speed": {
                            "type": "boolean",
                            "description": "Enable advanced unhooking"
                        },
                        "cfg": {
                            "type": "boolean",
                            "description": "Disable Control Flow Guard"
                        },
                        "self_deletion": {
                            "type": "boolean",
                            "description": "Enable self-deletion"
                        },
                        "anti_forensic": {
                            "type": "boolean",
                            "description": "Enable anti-forensic cleanup"
                        },
                        "dll": {
                            "type": "boolean",
                            "description": "Compile as DLL"
                        },
                        "cpl": {
                            "type": "boolean",
                            "description": "Compile as CPL"
                        },
                        "entropy": {
                            "type": "integer",
                            "enum": [1, 2],
                            "description": "Entropy reduction (1: null, 2: pokemon)"
                        },
                        "sign_certificate": {
                            "type": "string",
                            "description": "Website or file path for signing"
                        },
                        "sgn_encode": {
                            "type": "boolean",
                            "description": "Apply Shikata Ga Nai polymorphic encoding"
                        },
                        "stardust": {
                            "type": "boolean",
                            "description": "Use Stardust PIC generator (input must be .bin)"
                        },
                        "syswhisper": {
                            "type": "integer",
                            "enum": [1, 2],
                            "description": "Direct syscalls: 1=random jumps, 2=MingW+NASM"
                        },
                        "junk_api": {
                            "type": "boolean",
                            "description": "Insert benign API calls for mimicry attacks"
                        },
                        "mllvm": {
                            "type": "string",
                            "description": "Custom LLVM passes (comma-separated)"
                        },
                        "binder": {
                            "type": "string",
                            "description": "Path to utility for binding (default: binder/calc.exe)"
                        },
                        "watermark": {
                            "type": "boolean",
                            "description": "Add watermark to binary"
                        },
                        "icon": {
                            "type": "boolean",
                            "description": "Enable icon for output binary"
                        },
                        "detect_hooks": {
                            "type": "boolean",
                            "description": "Compile check_hook.exe for detecting hooks"
                        },
                        "divide": {
                            "type": "boolean",
                            "description": "Enable divide and conquer for AES2"
                        }
                    },
                    "required": ["input_file", "output_file"]
                }
            ),
            Tool(
                name="list_loaders",
                description="List available BOAZ process injection loaders",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "category": {
                            "type": "string",
                            "enum": ["syscall", "userland", "stealth", "memory_guard",
                                   "veh_vch", "threadless", "all"],
                            "description": "Filter by loader category"
                        }
                    }
                }
            ),
            Tool(
                name="list_encoders",
                description="List supported payload encoding schemes",
                inputSchema={
                    "type": "object",
                    "properties": {}
                }
            ),
            Tool(
                name="analyze_binary",
                description="Analyze binary characteristics and entropy",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to binary file"
                        }
                    },
                    "required": ["file_path"]
                }
            ),
            Tool(
                name="validate_options",
                description="Validate BOAZ configuration parameters",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "loader": {"type": "integer"},
                        "encoding": {"type": "string"},
                        "compiler": {"type": "string"}
                    }
                }
            )
        ]

    async def call_tool(self, name: str, arguments: dict) -> list[TextContent]:
        """Execute BOAZ tool"""
        logger.info(f"Tool called: {name}")
        try:
            if name == "generate_payload":
                return await self._generate_payload(arguments)
            elif name == "list_loaders":
                return await self._list_loaders(arguments)
            elif name == "list_encoders":
                return await self._list_encoders()
            elif name == "analyze_binary":
                return await self._analyze_binary(arguments)
            elif name == "validate_options":
                return await self._validate_options(arguments)
            else:
                logger.error(f"Unknown tool requested: {name}")
                raise ValueError(f"Unknown tool: {name}")
        except FileNotFoundError as e:
            logger.error(f"File not found: {e}")
            return [TextContent(type="text", text=f"❌ File not found: {str(e)}")]
        except ValueError as e:
            logger.error(f"Validation error: {e}")
            return [TextContent(type="text", text=f"❌ Validation error: {str(e)}")]
        except subprocess.TimeoutExpired as e:
            logger.error(f"Timeout error: {e}")
            return [TextContent(type="text", text=f"❌ Operation timed out: {str(e)}")]
        except PermissionError as e:
            logger.error(f"Permission error: {e}")
            return [TextContent(type="text", text=f"❌ Permission denied: {str(e)}")]
        except Exception as e:
            logger.exception(f"Unexpected error in {name}")
            return [TextContent(type="text", text=f"❌ Internal error: {str(e)}")]

    async def _generate_payload(self, args: dict) -> list[TextContent]:
        """Generate evasive payload"""
        logger.info(f"Generating payload: {args.get('input_file')} -> {args.get('output_file')}")

        # Validate and sanitize paths
        input_file = self._validate_path(args["input_file"], must_exist=True)
        output_file = self._validate_path(args["output_file"], must_exist=False)

        # Check input file size
        self._check_file_size(input_file)

        # Validate optional parameters
        if "loader" in args:
            self._validate_loader(args["loader"])
        if "encoding" in args:
            self._validate_encoding(args["encoding"])
        if "compiler" in args:
            self._validate_compiler(args["compiler"])
        if "shellcode_type" in args:
            self._validate_shellcode_type(args["shellcode_type"])

        # Sanitize string parameters
        if "sign_certificate" in args:
            args["sign_certificate"] = self._sanitize_string(args["sign_certificate"], "sign_certificate")
        if "mllvm" in args:
            args["mllvm"] = self._sanitize_string(args["mllvm"], "mllvm")
        if "binder" in args:
            binder_path = self._validate_path(args["binder"], must_exist=False)
            args["binder"] = binder_path

        cmd = ["python3", self.boaz_script]

        # Required arguments (use validated paths)
        cmd.extend(["-f", input_file])
        cmd.extend(["-o", output_file])

        # Optional arguments
        if "loader" in args:
            cmd.extend(["-l", str(args["loader"])])
        if "encoding" in args:
            cmd.extend(["-e", args["encoding"]])
        if "compiler" in args:
            cmd.extend(["-c", args["compiler"]])
        if "shellcode_type" in args:
            cmd.extend(["-t", args["shellcode_type"]])

        # Boolean flags
        if args.get("obfuscate"):
            cmd.append("-obf")
        if args.get("obfuscate_api"):
            cmd.append("-obf_api")
        if args.get("anti_emulation"):
            cmd.append("-a")
        if args.get("sleep"):
            cmd.append("-sleep")
        if args.get("etw"):
            cmd.append("-etw")
        if args.get("api_unhooking"):
            cmd.append("-u")
        if args.get("god_speed"):
            cmd.append("-g")
        if args.get("cfg"):
            cmd.append("-cfg")
        if args.get("self_deletion"):
            cmd.append("-d")
        if args.get("anti_forensic"):
            cmd.append("-af")
        if args.get("dll"):
            cmd.append("-dll")
        if args.get("cpl"):
            cmd.append("-cpl")

        # Integer options
        if "dream" in args:
            cmd.extend(["-dream", str(args["dream"])])
        if "entropy" in args:
            cmd.extend(["-entropy", str(args["entropy"])])
        if "syswhisper" in args:
            cmd.extend(["-w", str(args["syswhisper"])])

        # String options
        if "sign_certificate" in args:
            cmd.extend(["-s", args["sign_certificate"]])
        if "mllvm" in args:
            cmd.extend(["-mllvm", args["mllvm"]])
        if "binder" in args:
            cmd.extend(["-b", args["binder"]])

        # Additional boolean flags
        if args.get("sgn_encode"):
            cmd.append("-sgn")
        if args.get("stardust"):
            cmd.append("-sd")
        if args.get("junk_api"):
            cmd.append("-j")
        if args.get("watermark"):
            cmd.append("-wm")
        if args.get("icon"):
            cmd.append("-icon")
        if args.get("detect_hooks"):
            cmd.append("-dh")
        if args.get("divide"):
            cmd.append("-divide")

        # Execute with timeout
        try:
            logger.info(f"Executing BOAZ command: {' '.join(cmd[:5])}...")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.boaz_path,
                timeout=self.SUBPROCESS_TIMEOUT
            )

            output = f"STDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"
            if result.returncode == 0:
                logger.info(f"Payload generated successfully: {args['output_file']}")
                output = f"✅ Payload generated successfully at {args['output_file']}\n\n{output}"
            else:
                logger.error(f"Payload generation failed with exit code {result.returncode}")
                output = f"❌ Error generating payload (exit code {result.returncode})\n\n{output}"

            return [TextContent(type="text", text=output)]

        except subprocess.TimeoutExpired:
            logger.error(f"Payload generation timed out after {self.SUBPROCESS_TIMEOUT} seconds")
            raise ValueError(f"Operation timed out after {self.SUBPROCESS_TIMEOUT} seconds")
        except FileNotFoundError as e:
            logger.error(f"File not found during execution: {e}")
            raise
        except Exception as e:
            logger.exception("Unexpected error during payload generation")
            raise

    async def _list_loaders(self, args: dict) -> list[TextContent]:
        """List available loaders"""
        loaders = LOADER_REFERENCE

        category = args.get("category", "all")
        if category != "all":
            loaders = {k: v for k, v in loaders.items()
                      if v.get("category") == category}

        output = "# BOAZ Loaders\n\n"
        for num, info in sorted(loaders.items()):
            output += f"**Loader {num}**: {info['name']}\n"
            output += f"  Category: {info['category']}\n"
            output += f"  Description: {info['description']}\n"
            if info.get("encoding_required"):
                output += f"  Required Encoding: {info['encoding_required']}\n"
            output += "\n"

        return [TextContent(type="text", text=output)]

    async def _list_encoders(self) -> list[TextContent]:
        """List encoding schemes"""
        encoders = ENCODING_REFERENCE

        output = "# BOAZ Encoding Schemes\n\n"
        for name, info in encoders.items():
            output += f"**{name}**: {info['description']}\n"
            output += f"  Strength: {info['strength']}\n"
            output += f"  Speed: {info['speed']}\n"
            output += f"  Use case: {info['use_case']}\n\n"

        return [TextContent(type="text", text=output)]

    async def _analyze_binary(self, args: dict) -> list[TextContent]:
        """Analyze binary file"""
        logger.info(f"Analyzing binary: {args.get('file_path')}")

        # Validate and sanitize path
        file_path = self._validate_path(args["file_path"], must_exist=True)

        # Check file size before reading
        self._check_file_size(file_path)

        # Basic analysis
        size = os.path.getsize(file_path)

        # Read file and calculate entropy
        with open(file_path, "rb") as f:
            data = f.read()

        # Shannon entropy calculation
        import math
        from collections import Counter

        counter = Counter(data)
        entropy = 0
        for count in counter.values():
            p = count / len(data)
            entropy -= p * math.log2(p)

        output = f"# Binary Analysis: {file_path}\n\n"
        output += f"📁 Size: {size} bytes ({size/1024:.2f} KB)\n"
        output += f"📊 Entropy: {entropy:.4f} (0-8 scale)\n\n"

        if entropy > 7.5:
            output += "🔴 HIGH ENTROPY - Likely encrypted/packed\n"
        elif entropy > 6.5:
            output += "🟡 MEDIUM ENTROPY - May trigger heuristics\n"
        else:
            output += "🟢 LOW ENTROPY - Good for evasion\n"

        output += f"\n💡 Recommendation: "
        if entropy > 7.0:
            output += "Use -entropy 1 or 2 to reduce entropy"
        else:
            output += "Entropy is acceptable"

        logger.info(f"Binary analysis complete: {file_path}, entropy={entropy:.4f}")
        return [TextContent(type="text", text=output)]

    async def _validate_options(self, args: dict) -> list[TextContent]:
        """Validate configuration"""
        issues = []

        # Validate loader
        if "loader" in args:
            loader = args["loader"]
            if loader not in LOADER_REFERENCE:
                issues.append(f"Loader {loader} not found")
            else:
                loader_info = LOADER_REFERENCE[loader]
                if "encoding" in args and loader_info.get("encoding_required"):
                    if args["encoding"] != loader_info["encoding_required"]:
                        issues.append(
                            f"Loader {loader} requires encoding: "
                            f"{loader_info['encoding_required']}"
                        )

        # Validate encoding
        if "encoding" in args:
            if args["encoding"] not in ENCODING_REFERENCE:
                issues.append(f"Unknown encoding: {args['encoding']}")

        # Validate compiler
        if "compiler" in args:
            valid_compilers = ["mingw", "pluto", "akira"]
            if args["compiler"] not in valid_compilers:
                issues.append(f"Unknown compiler: {args['compiler']}")

        if issues:
            output = "❌ Validation Failed:\n\n" + "\n".join(f"- {issue}" for issue in issues)
        else:
            output = "✅ Configuration valid"

        return [TextContent(type="text", text=output)]

    async def run(self):
        """Run the MCP server"""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options()
            )


# Loader reference data
LOADER_REFERENCE = {
    1: {
        "name": "Proxy Syscall + Custom Call Stack",
        "category": "syscall",
        "description": "Custom call stack with indirect syscall and threadless execution"
    },
    2: {
        "name": "APC Test Alert",
        "category": "syscall",
        "description": "APC-based testing mechanism"
    },
    3: {
        "name": "Sifu Syscall",
        "category": "syscall",
        "description": "Direct syscall implementation"
    },
    4: {
        "name": "UUID Manual Injection",
        "category": "syscall",
        "description": "Manual injection with UUID-encoded payload",
        "encoding_required": "uuid"
    },
    5: {
        "name": "Remote MockingJay",
        "category": "syscall",
        "description": "Remote process injection technique"
    },
    6: {
        "name": "Local Thread Hijacking",
        "category": "syscall",
        "description": "Hijacks existing thread for execution"
    },
    7: {
        "name": "Function Pointer Invoke",
        "category": "syscall",
        "description": "Local injection via function pointer"
    },
    8: {
        "name": "Ninja Syscall 2",
        "category": "syscall",
        "description": "Advanced syscall variant"
    },
    9: {
        "name": "RW Local MockingJay",
        "category": "syscall",
        "description": "Read-write MockingJay technique"
    },
    10: {
        "name": "Ninja Syscall 1",
        "category": "syscall",
        "description": "Ninja syscall implementation"
    },
    11: {
        "name": "Sifu Divide and Conquer",
        "category": "syscall",
        "description": "Syscall with divided execution",
        "encoding_required": "aes2"
    },
    14: {
        "name": "Exit Without Execution",
        "category": "userland",
        "description": "Testing loader that exits without execution"
    },
    15: {
        "name": "SysWhispers2 Classic",
        "category": "userland",
        "description": "Classic native API calls via SysWhispers2"
    },
    16: {
        "name": "Classic Userland APIs",
        "category": "userland",
        "description": "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread"
    },
    17: {
        "name": "Sifu Syscall Divide & Conquer",
        "category": "syscall",
        "description": "Advanced Sifu syscall with divided execution"
    },
    18: {
        "name": "WriteProcessMemoryAPC",
        "category": "userland",
        "description": "Userland API with APC write method"
    },
    19: {
        "name": "DLL Overloading",
        "category": "stealth",
        "description": "DLL overloading technique"
    },
    20: {
        "name": "Stealth Injection (APC + DLL)",
        "category": "stealth",
        "description": "WriteProcessMemoryAPC with DLL overloading"
    },
    22: {
        "name": "Advanced Custom Call Stack",
        "category": "stealth",
        "description": "Indirect syscall with VEH->VCH and handler cleanup"
    },
    24: {
        "name": "Classic Native API",
        "category": "userland",
        "description": "Standard native API calls"
    },
    26: {
        "name": "Stealth Injection Advanced",
        "category": "stealth",
        "description": "3 APC variants + DLL overloading + dynamic API hashing"
    },
    27: {
        "name": "Stealth + Halo's Gate",
        "category": "stealth",
        "description": "Advanced injection with Halo's Gate patching"
    },
    28: {
        "name": "Halo's Gate + Custom Write",
        "category": "stealth",
        "description": "Halo's Gate with MAC/UUID write + invisible loading"
    },
    29: {
        "name": "Classic Indirect Syscall",
        "category": "syscall",
        "description": "Indirect syscall implementation"
    },
    30: {
        "name": "Classic Direct Syscall",
        "category": "syscall",
        "description": "Direct syscall implementation"
    },
    31: {
        "name": "MAC Address Injection",
        "category": "stealth",
        "description": "Payload encoded as MAC addresses",
        "encoding_required": "mac"
    },
    32: {
        "name": "Stealth Advanced",
        "category": "stealth",
        "description": "Advanced stealth injection"
    },
    33: {
        "name": "Indirect Syscall + Halo + Custom Stack",
        "category": "stealth",
        "description": "Combined stealth techniques"
    },
    34: {
        "name": "EDR Syscall No.1",
        "category": "stealth",
        "description": "EDR syscall with Halo's Gate and custom stack"
    },
    36: {
        "name": "EDR Syscall No.2",
        "category": "stealth",
        "description": "Alternative EDR syscall implementation"
    },
    37: {
        "name": "Stealth Memory Scan Evasion",
        "category": "stealth",
        "description": "Advanced loader with memory scan evasion"
    },
    38: {
        "name": "Phantom DLL Overloading",
        "category": "stealth",
        "description": "APC write with phantom DLL execution"
    },
    39: {
        "name": "Custom Stack PI Remote",
        "category": "stealth",
        "description": "Remote PI with threadless execution"
    },
    40: {
        "name": "Threadless DLL Notification",
        "category": "stealth",
        "description": "Threadless DLL notification execution"
    },
    41: {
        "name": "Decoy Code Execution",
        "category": "stealth",
        "description": "Remote PI with decoy code"
    },
    48: {
        "name": "Sifu Breakpoint Handler (NtResumeThread)",
        "category": "memory_guard",
        "description": "Memory guard with breakpoint on NtResumeThread"
    },
    49: {
        "name": "Sifu Breakpoint Handler (NtCreateThreadEx)",
        "category": "memory_guard",
        "description": "Memory guard with decoy, PAGE_NOACCESS, XOR"
    },
    51: {
        "name": "Sifu Breakpoint Handler (RtlUserThreadStart)",
        "category": "memory_guard",
        "description": "Advanced memory guard on multiple hooks"
    },
    52: {
        "name": "ROP Gadget Trampoline",
        "category": "memory_guard",
        "description": "ROP gadgets for execution trampoline"
    },
    54: {
        "name": "Exception + Breakpoint Handler",
        "category": "memory_guard",
        "description": "Combined exception and breakpoint handling"
    },
    56: {
        "name": "Loader 37 + PEB Module",
        "category": "stealth",
        "description": "Stealth loader with manual PEB module addition"
    },
    57: {
        "name": "RC4 Memory Guard",
        "category": "memory_guard",
        "description": "Loader 51 variant with RC4 encryption"
    },
    58: {
        "name": "VEH + ROP Trampoline",
        "category": "veh_vch",
        "description": "VEH handler with ROP trampoline"
    },
    59: {
        "name": "SEH + ROP Trampoline",
        "category": "veh_vch",
        "description": "SEH handler with ROP trampoline"
    },
    60: {
        "name": "Page Guard Debug Registers",
        "category": "veh_vch",
        "description": "Page guard to set debug registers without Get/SetContext"
    },
    61: {
        "name": "Page Guard VEH/VCH",
        "category": "veh_vch",
        "description": "Page guard + VEH breakpoints + VCH execution"
    },
    63: {
        "name": "Remote Module Injection",
        "category": "stealth",
        "description": "Remote version of custom module loader 37"
    },
    65: {
        "name": "VMT Hooking + Module Loader",
        "category": "threadless",
        "description": "Virtual table hooking with custom module loader"
    },
    66: {
        "name": "VMT + PPID Spoofing",
        "category": "threadless",
        "description": "VMT hooking with PPID spoofing and mitigation policies"
    },
    67: {
        "name": "VMT + Trampoline",
        "category": "threadless",
        "description": "VMT with strange trampoline code"
    },
    69: {
        "name": "Manual VEH/VCH + PEB Cleanup",
        "category": "veh_vch",
        "description": "Manual handler setup with PEB CrossProcessFlags cleanup"
    },
    73: {
        "name": "VT Pointer Threadless",
        "category": "threadless",
        "description": "Virtual table pointer threadless injection with memory guard"
    },
    74: {
        "name": "VT Pointer + Pretext",
        "category": "threadless",
        "description": "VT threadless with VirtualProtect in pretext"
    },
    75: {
        "name": ".NET JIT Threadless",
        "category": "threadless",
        "description": "Dotnet JIT threadless process injection"
    },
    76: {
        "name": "PEB Entrypoint Threadless",
        "category": "threadless",
        "description": "Module list PEB entrypoint hijacking"
    },
    77: {
        "name": "RtlCreateHeap VT Pointer",
        "category": "threadless",
        "description": "VT pointer using RtlCreateHeap instead of BaseThreadInitThunk"
    }
}

# Encoding reference data
ENCODING_REFERENCE = {
    "uuid": {
        "description": "Universally Unique Identifier format",
        "strength": "Medium",
        "speed": "Fast",
        "use_case": "Low entropy, legitimate-looking format"
    },
    "xor": {
        "description": "Simple XOR encryption",
        "strength": "Low",
        "speed": "Very Fast",
        "use_case": "Quick obfuscation, testing"
    },
    "mac": {
        "description": "MAC address format encoding",
        "strength": "Medium",
        "speed": "Fast",
        "use_case": "Network-themed obfuscation"
    },
    "ipv4": {
        "description": "IPv4 address format encoding",
        "strength": "Medium",
        "speed": "Fast",
        "use_case": "Network-related obfuscation"
    },
    "base45": {
        "description": "Base45 encoding",
        "strength": "Low",
        "speed": "Fast",
        "use_case": "Alternative to Base64"
    },
    "base64": {
        "description": "Standard Base64 encoding",
        "strength": "Low",
        "speed": "Very Fast",
        "use_case": "Common encoding, may be flagged"
    },
    "base58": {
        "description": "Base58 encoding (Bitcoin-style)",
        "strength": "Low",
        "speed": "Fast",
        "use_case": "Alternative base encoding"
    },
    "aes": {
        "description": "AES encryption",
        "strength": "High",
        "speed": "Medium",
        "use_case": "Strong encryption, higher entropy"
    },
    "aes2": {
        "description": "AES with divide-and-conquer decryption",
        "strength": "High",
        "speed": "Medium",
        "use_case": "Bypass logical path hijacking"
    },
    "des": {
        "description": "DES encryption (SystemFunction002)",
        "strength": "Medium",
        "speed": "Medium",
        "use_case": "System API-based encryption"
    },
    "chacha": {
        "description": "ChaCha20 stream cipher",
        "strength": "High",
        "speed": "Fast",
        "use_case": "Modern encryption, less fingerprinted"
    },
    "rc4": {
        "description": "RC4 encryption (SystemFunction032/033)",
        "strength": "Medium",
        "speed": "Fast",
        "use_case": "System API-based encryption"
    }
}


if __name__ == "__main__":
    server = BoazMCPServer()
    asyncio.run(server.run())
