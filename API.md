# BOAZ MCP API Reference

Complete Model Context Protocol (MCP) tool reference for BOAZ integration.

## Table of Contents

- [Overview](#overview)
- [MCP Server Architecture](#mcp-server-architecture)
- [Available Tools](#available-tools)
- [Loader Reference](#loader-reference)
- [Encoding Reference](#encoding-reference)
- [Error Handling](#error-handling)
- [Examples](#examples)

## Overview

The BOAZ MCP server provides AI assistants with controlled access to BOAZ's evasion framework capabilities through standardized MCP tools. This enables natural language interaction with complex payload generation workflows.

### Protocol Version
- MCP Version: 1.0
- BOAZ API Version: 1.0

### Server Configuration

The MCP server runs as a subprocess managed by Claude Desktop or other MCP-compatible clients.

**Entry Point**: `boaz_mcp/server.py`

**Environment Variables**:
- `BOAZ_PATH`: Path to BOAZ_beta directory (required)
- `BOAZ_OUTPUT_DIR`: Default output directory (optional, default: `./output`)

## MCP Server Architecture

### Server Implementation

```python
#!/usr/bin/env python3
"""
BOAZ MCP Server
Provides MCP interface to BOAZ evasion framework
"""

import asyncio
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent


class BoazMCPServer:
    """MCP server for BOAZ framework integration"""

    def __init__(self):
        self.server = Server("boaz")
        self.boaz_path = os.getenv("BOAZ_PATH")
        if not self.boaz_path:
            raise ValueError("BOAZ_PATH environment variable not set")

        self.boaz_script = os.path.join(self.boaz_path, "Boaz.py")
        if not os.path.exists(self.boaz_script):
            raise FileNotFoundError(f"Boaz.py not found at {self.boaz_script}")

        # Register tool handlers
        self.server.list_tools()(self.list_tools)
        self.server.call_tool()(self.call_tool)

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
                            "enum": ["donut", "pe2sh", "rc4", "amber", "shoggoth"],
                            "default": "donut",
                            "description": "Shellcode generator"
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
                raise ValueError(f"Unknown tool: {name}")
        except Exception as e:
            return [TextContent(type="text", text=f"Error: {str(e)}")]

    async def _generate_payload(self, args: dict) -> list[TextContent]:
        """Generate evasive payload"""
        cmd = ["python3", self.boaz_script]

        # Required arguments
        cmd.extend(["-f", args["input_file"]])
        cmd.extend(["-o", args["output_file"]])

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

        # String options
        if "sign_certificate" in args:
            cmd.extend(["-s", args["sign_certificate"]])

        # Execute
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.boaz_path)

        output = f"STDOUT:\\n{result.stdout}\\n\\nSTDERR:\\n{result.stderr}"
        if result.returncode == 0:
            output = f"Payload generated successfully at {args['output_file']}\\n\\n{output}"
        else:
            output = f"Error generating payload (exit code {result.returncode})\\n\\n{output}"

        return [TextContent(type="text", text=output)]

    async def _list_loaders(self, args: dict) -> list[TextContent]:
        """List available loaders"""
        loaders = LOADER_REFERENCE

        category = args.get("category", "all")
        if category != "all":
            loaders = {k: v for k, v in loaders.items()
                      if v.get("category") == category}

        output = "# BOAZ Loaders\\n\\n"
        for num, info in sorted(loaders.items()):
            output += f"**Loader {num}**: {info['name']}\\n"
            output += f"  Category: {info['category']}\\n"
            output += f"  Description: {info['description']}\\n"
            if info.get("encoding_required"):
                output += f"  Required Encoding: {info['encoding_required']}\\n"
            output += "\\n"

        return [TextContent(type="text", text=output)]

    async def _list_encoders(self) -> list[TextContent]:
        """List encoding schemes"""
        encoders = ENCODING_REFERENCE

        output = "# BOAZ Encoding Schemes\\n\\n"
        for name, info in encoders.items():
            output += f"**{name}**: {info['description']}\\n"
            output += f"  Strength: {info['strength']}\\n"
            output += f"  Speed: {info['speed']}\\n"
            output += f"  Use case: {info['use_case']}\\n\\n"

        return [TextContent(type="text", text=output)]

    async def _analyze_binary(self, args: dict) -> list[TextContent]:
        """Analyze binary file"""
        file_path = args["file_path"]

        if not os.path.exists(file_path):
            return [TextContent(type="text", text=f"File not found: {file_path}")]

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

        output = f"# Binary Analysis: {file_path}\\n\\n"
        output += f"Size: {size} bytes ({size/1024:.2f} KB)\\n"
        output += f"Entropy: {entropy:.4f} (0-8 scale)\\n\\n"

        if entropy > 7.5:
            output += "HIGH ENTROPY - Likely encrypted/packed\\n"
        elif entropy > 6.5:
            output += "MEDIUM ENTROPY - May trigger heuristics\\n"
        else:
            output += "LOW ENTROPY - Good for evasion\\n"

        output += f"\\nRecommendation: "
        if entropy > 7.0:
            output += "Use -entropy 1 or 2 to reduce entropy"
        else:
            output += "Entropy is acceptable"

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
            output = "Validation Failed:\\n\\n" + "\\n".join(f"- {issue}" for issue in issues)
        else:
            output = "Configuration valid"

        return [TextContent(type="text", text=output)]

    async def run(self):
        """Run the MCP server"""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(read_stream, write_stream)


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
```

## Available Tools

### 1. generate_payload

Generate evasive payload using BOAZ framework.

**Input Schema**:
```json
{
  "input_file": "string (required)",
  "output_file": "string (required)",
  "loader": "integer (default: 16)",
  "encoding": "enum [uuid, xor, mac, ipv4, base45, base64, base58, aes, des, chacha, rc4, aes2]",
  "compiler": "enum [mingw, pluto, akira] (default: mingw)",
  "shellcode_type": "enum [donut, pe2sh, rc4, amber, shoggoth] (default: donut)",
  "obfuscate": "boolean",
  "obfuscate_api": "boolean",
  "anti_emulation": "boolean",
  "sleep": "boolean",
  "dream": "integer (milliseconds)",
  "etw": "boolean",
  "api_unhooking": "boolean",
  "god_speed": "boolean",
  "cfg": "boolean",
  "self_deletion": "boolean",
  "anti_forensic": "boolean",
  "dll": "boolean",
  "cpl": "boolean",
  "entropy": "enum [1, 2]",
  "sign_certificate": "string (URL or file path)"
}
```

**Example**:
```json
{
  "input_file": "/path/to/payload.exe",
  "output_file": "/path/to/output.exe",
  "loader": 37,
  "encoding": "aes",
  "compiler": "akira",
  "obfuscate": true,
  "anti_emulation": true,
  "etw": true
}
```

**Returns**: Text content with generation status and output

### 2. list_loaders

List available process injection loaders.

**Input Schema**:
```json
{
  "category": "enum [syscall, userland, stealth, memory_guard, veh_vch, threadless, all]"
}
```

**Example**:
```json
{
  "category": "memory_guard"
}
```

**Returns**: Formatted list of loaders with descriptions

### 3. list_encoders

List supported payload encoding schemes.

**Input Schema**: Empty object `{}`

**Returns**: Formatted list of encoders with characteristics

### 4. analyze_binary

Analyze binary characteristics and entropy.

**Input Schema**:
```json
{
  "file_path": "string (required)"
}
```

**Example**:
```json
{
  "file_path": "/path/to/binary.exe"
}
```

**Returns**: Binary analysis including size, entropy, and recommendations

### 5. validate_options

Validate BOAZ configuration parameters.

**Input Schema**:
```json
{
  "loader": "integer",
  "encoding": "string",
  "compiler": "string"
}
```

**Example**:
```json
{
  "loader": 4,
  "encoding": "uuid",
  "compiler": "akira"
}
```

**Returns**: Validation results and any compatibility issues

## Loader Reference

### Syscall Category (1-11)

Advanced syscall-based injection techniques.

| Loader | Name | Features |
|--------|------|----------|
| 1 | Proxy Syscall | Custom call stack, threadless |
| 3 | Sifu Syscall | Direct syscall implementation |
| 4 | UUID Manual | Requires UUID encoding |
| 8 | Ninja Syscall 2 | Advanced syscall variant |
| 10 | Ninja Syscall 1 | Ninja implementation |
| 11 | Sifu Divide & Conquer | Requires AES2 encoding |

### Userland Category (14-18)

Classic API-based techniques.

| Loader | Name | Features |
|--------|------|----------|
| 15 | SysWhispers2 | Native API via SysWhispers2 |
| 16 | Classic APIs | Most compatible, well-tested |
| 18 | APC Write | Alternative execution method |

### Stealth Category (19-41)

Advanced stealth injection methods.

| Loader | Name | Features |
|--------|------|----------|
| 19 | DLL Overloading | DLL overloading technique |
| 26 | Stealth Advanced | 3 APC variants + hashing |
| 27 | Stealth + Halo's Gate | With Halo's Gate patching |
| 37 | Memory Scan Evasion | Best general-purpose stealth |
| 38 | Phantom DLL | APC + phantom execution |

### Memory Guard Category (48-57)

Hardware breakpoint-based memory protection.

| Loader | Name | Features |
|--------|------|----------|
| 48 | Sifu BP (NtResumeThread) | Basic memory guard |
| 49 | Sifu BP (NtCreateThreadEx) | With decoy and XOR |
| 51 | Sifu BP (RtlUserThreadStart) | Multiple hooks, advanced |
| 57 | RC4 Memory Guard | SystemFunction032/033 encryption |

### VEH/VCH Category (58-69)

Exception handler-based execution.

| Loader | Name | Features |
|--------|------|----------|
| 58 | VEH + ROP | VEH with ROP trampoline |
| 60 | Page Guard Debug | Sets debug registers via page guard |
| 61 | Page Guard VEH/VCH | Most advanced exception-based |
| 69 | Manual VEH/VCH | With PEB cleanup |

### Threadless Category (73-77)

No thread creation required.

| Loader | Name | Features |
|--------|------|----------|
| 73 | VT Pointer | Virtual table hijacking |
| 75 | .NET JIT | JIT compilation hijacking |
| 77 | RtlCreateHeap VT | Heap-based VT manipulation |

## Encoding Reference

### UUID
- **Strength**: Medium
- **Speed**: Fast
- **Entropy**: Low
- **Use Case**: General-purpose, legitimate-looking

### AES
- **Strength**: High
- **Speed**: Medium
- **Entropy**: High
- **Use Case**: Strong encryption needed

### AES2 (Divide & Conquer)
- **Strength**: High
- **Speed**: Medium
- **Entropy**: High
- **Use Case**: Bypass logical path hijacking
- **Compatible Loaders**: 11, 17

### ChaCha20
- **Strength**: High
- **Speed**: Fast
- **Entropy**: High
- **Use Case**: Modern cipher, less fingerprinted

### RC4
- **Strength**: Medium
- **Speed**: Fast
- **Entropy**: Medium
- **Use Case**: System API encryption (SystemFunction032/033)

### MAC
- **Strength**: Medium
- **Speed**: Fast
- **Entropy**: Low
- **Use Case**: Network-themed obfuscation
- **Compatible Loaders**: 31

## Error Handling

### Common Errors

**Error**: `BOAZ_PATH environment variable not set`
- **Cause**: MCP configuration missing BOAZ_PATH
- **Solution**: Add `"BOAZ_PATH"` to env in mcp_config.json

**Error**: `Boaz.py not found`
- **Cause**: Incorrect BOAZ_PATH
- **Solution**: Verify path points to BOAZ_beta directory

**Error**: `Loader X not found`
- **Cause**: Invalid loader number
- **Solution**: Use list_loaders tool to see available loaders

**Error**: `Loader X requires encoding: Y`
- **Cause**: Incompatible encoding for loader
- **Solution**: Use validate_options tool before generation

**Error**: `File not found: input.exe`
- **Cause**: Invalid input file path
- **Solution**: Verify input file exists and path is correct

## Examples

### Example 1: Basic Payload with MCP

```python
# Tool call
{
  "tool": "generate_payload",
  "arguments": {
    "input_file": "/home/user/payload.exe",
    "output_file": "/home/user/output.exe",
    "loader": 16,
    "encoding": "uuid"
  }
}

# Response
"Payload generated successfully at /home/user/output.exe

STDOUT:
[!] Using Donut to generate shellcode from binary file
[+] Shellcode generated successfully
[+] Loader 16 selected
[+] UUID encoding applied
[+] Compilation successful
..."
```

### Example 2: Advanced Configuration

```python
{
  "tool": "generate_payload",
  "arguments": {
    "input_file": "/home/user/beacon.exe",
    "output_file": "/home/user/evasive_beacon.exe",
    "loader": 51,
    "encoding": "aes",
    "compiler": "akira",
    "shellcode_type": "donut",
    "obfuscate": true,
    "obfuscate_api": true,
    "anti_emulation": true,
    "dream": 2000,
    "etw": true,
    "cfg": true,
    "self_deletion": true,
    "anti_forensic": true,
    "entropy": 2
  }
}
```

### Example 3: List Specific Loader Category

```python
{
  "tool": "list_loaders",
  "arguments": {
    "category": "threadless"
  }
}

# Response
"# BOAZ Loaders

**Loader 73**: VT Pointer Threadless
  Category: threadless
  Description: Virtual table pointer threadless injection with memory guard

**Loader 74**: VT Pointer + Pretext
  Category: threadless
  Description: VT threadless with VirtualProtect in pretext
..."
```

### Example 4: Validate Configuration

```python
{
  "tool": "validate_options",
  "arguments": {
    "loader": 4,
    "encoding": "xor",
    "compiler": "akira"
  }
}

# Response
"Validation Failed:

- Loader 4 requires encoding: uuid"
```

### Example 5: Analyze Binary

```python
{
  "tool": "analyze_binary",
  "arguments": {
    "file_path": "/home/user/suspicious.exe"
  }
}

# Response
"# Binary Analysis: /home/user/suspicious.exe

Size: 524288 bytes (512.00 KB)
Entropy: 7.8234 (0-8 scale)

HIGH ENTROPY - Likely encrypted/packed

Recommendation: Use -entropy 1 or 2 to reduce entropy"
```

## Integration Patterns

### Pattern 1: AI-Guided Loader Selection

```
User: What's the best loader for EDR evasion?

AI: Let me check the available loaders.
[Calls list_loaders with category="stealth"]

Based on the analysis, I recommend:
1. Loader 37 - Comprehensive memory scan evasion
2. Loader 51 - Advanced with memory guard
3. Loader 69 - Most sophisticated with PEB cleanup
```

### Pattern 2: Validation Before Generation

```
User: Generate payload with loader 4 and AES encoding

AI: Let me validate this configuration first.
[Calls validate_options]

Error: Loader 4 requires UUID encoding, not AES.
Would you like me to:
1. Use UUID encoding with loader 4
2. Choose a different loader compatible with AES
```

### Pattern 3: Entropy Analysis Workflow

```
User: My payload keeps getting detected

AI: Let me analyze the binary first.
[Calls analyze_binary]

The entropy is 7.9 which is very high. I recommend:
1. Add -entropy 2 to reduce entropy
2. Use stronger obfuscation with Akira compiler
3. Apply anti-forensic cleanup

Shall I generate an updated version?
```

## Best Practices

### 1. Always Validate First

```python
# Bad - Direct generation
generate_payload(loader=4, encoding="aes")

# Good - Validate then generate
validate_options(loader=4, encoding="aes")
# Fix issues, then generate
generate_payload(loader=4, encoding="uuid")
```

### 2. Use Category Filtering

```python
# Bad - List all loaders
list_loaders()

# Good - Filter by use case
list_loaders(category="memory_guard")
```

### 3. Analyze Before Optimization

```python
# Bad - Random entropy reduction
generate_payload(entropy=1)

# Good - Analyze first
analyze_binary("output.exe")
# Then apply appropriate entropy reduction
generate_payload(entropy=2)
```

### 4. Progressive Enhancement

```python
# Start simple
generate_payload(loader=16, encoding="uuid")

# Add obfuscation
generate_payload(loader=16, encoding="uuid", compiler="akira")

# Add anti-analysis
generate_payload(loader=37, encoding="aes", compiler="akira",
                anti_emulation=True, etw=True)
```

## Security Considerations

### Authorization Required

All BOAZ MCP operations should only be performed:
- In authorized testing environments
- With documented approval
- For legitimate security research
- In compliance with laws and regulations

### Audit Logging

MCP server maintains logs of all operations:
- Tool invocations
- Parameters used
- Success/failure status
- Output file paths

### Access Control

Implement additional access controls:
- Restrict BOAZ_PATH permissions
- Limit output directory access
- Monitor MCP server logs
- Require authentication for sensitive operations

---

**API Version**: 1.0
**Last Updated**: 2025-01
**Maintained By**: BOAZ Development Team
