# BOAZ MCP Server

<div align="center">
  <img src="BOAZ-MCP.png" alt="BOAZ MCP Logo" width="300">
</div>

**BOAZ (Bypass, Obfuscate, Adapt, Zero-trace)** - MCP Integration for AI-Assisted Red Team Operations

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)

## Overview

BOAZ is a sophisticated evasion research framework designed for **authorized red team operations and security research**. This project extends BOAZ's capabilities by implementing a **Model Context Protocol (MCP) server** that enables AI assistants to interact with the framework through a standardized, secure interface.

### AI Agent Integration

This MCP implementation bridges the gap between advanced evasion techniques and AI-assisted security workflows. By wrapping BOAZ's powerful capabilities in an MCP server, security researchers and red team operators can now leverage AI assistants to:

- **Streamline payload generation** through natural language interactions
- **Access 77+ specialized loaders** and evasion techniques via standardized tools
- **Validate configurations** and analyze binaries through AI-guided workflows
- **Maintain security boundaries** with controlled, auditable access to sensitive operations

The MCP server provides a clean abstraction layer that allows AI agents to safely interact with BOAZ's complex evasion framework while maintaining proper authorization checks and operational security controls. This integration represents a significant advancement in making advanced red team tools more accessible and manageable through AI-assisted workflows.

> **WARNING**: This tool is intended for authorized security testing, research, and educational purposes only. Misuse of this tool may violate laws and regulations. Users are responsible for ensuring compliance with all applicable laws and obtaining proper authorization before use.

## Key Features

### Signature Evasion
- **LLVM IR-level Obfuscation**: Pluto and Akira LLVM-based obfuscation with string encryption and control flow flattening
- **Codebase Obfuscation**: Function name and string obfuscation using cryptographically secure random generators
- **Payload Encoding**: 12 encoding schemes (UUID, XOR, MAC, IPv4, Base45/64/58, ChaCha20, RC4, AES, AES2, DES)
- **SGN Polymorphic Encoding**: Shikata Ga Nai polymorphic encoder support
- **Compilation-time Obfuscation**: Bogus control flow, control flow flattening, MBA expressions, instruction substitution
- **Binary Hardening**: Stripped binaries, entropy reduction, signed certificates, metadata cloning, watermarking, icon support

### Heuristic Evasion
- **Anti-Emulation Techniques**: File system, process, and network-based checks
- **Junk API Injection**: Benign API sequences to vary call patterns and mimicry attacks
- **API Unhooking**: Multiple unhooking techniques including Halo's Gate and custom implementations
- **Direct Syscalls**: SysWhisper integration with random jump and MingW+NASM modes
- **Sleep Obfuscation**: Custom Ekko with stack encryption
- **PIC Conversion**: Support for Donut, PE2SH, RC4, Amber, Shoggoth, Stardust, Augment
- **Hook Detection**: Compile-time hook detection utility (check_hook.exe)

### Behavioral Evasion
- **77+ Process Injection Loaders**: Advanced code execution and process injection techniques
- **ETW Patching**: Both hot-patch and patchless ETW bypass methods
- **Parent PID Spoofing**: Process ancestry manipulation
- **CFG/XFG Support**: Code integrity mitigation bypass
- **Anti-Forensic Functions**: Post-execution trace removal
- **Binary Binding**: Utility binding capability for additional functionality
- **Custom LLVM Passes**: Support for user-defined LLVM obfuscation passes

## Quick Start

### Prerequisites
- Linux environment (Debian/Kali preferred)
- Python 3.8+
- Wine configured
- CMake, Git, GCC, G++, MingW, LLVM, NASM

### Installation

```bash
# Clone the repository
git clone https://github.com/Yenn503/BOAZ-MCP.git
cd BOAZ-MCP

# Run the setup script
chmod +x setup.sh
./setup.sh
```

For detailed installation instructions, see [INSTALL.md](INSTALL.md).

### Basic Usage

```bash
# Basic payload generation
cd BOAZ_beta
python3 Boaz.py -f /path/to/payload.exe -o output.exe -t donut -l 16 -e uuid

# With LLVM obfuscation
python3 Boaz.py -f payload.exe -o output.exe -t donut -l 16 -e uuid -c akira -obf

# Advanced options with anti-emulation
python3 Boaz.py -f payload.exe -o output.exe -t donut -l 37 -e aes -c pluto -a -sleep -etw -cfg
```

For comprehensive usage examples, see [USAGE.md](USAGE.md).

## MCP Server Integration

The BOAZ MCP server provides AI assistants with controlled access to BOAZ functionality through standardized tools:

### Available MCP Tools

1. **generate_payload** - Generate evasive payloads from PE files
2. **list_loaders** - Display available process injection loaders
3. **list_encoders** - Show supported encoding schemes
4. **analyze_binary** - Analyze binary characteristics and entropy
5. **validate_options** - Validate BOAZ configuration parameters

### For AI Assistants

If you're an AI assistant helping users with BOAZ-MCP, see **[AI_AGENTS.md](AI_AGENTS.md)** for:
- Complete tool usage patterns and workflows
- Best practices for AI-assisted payload generation
- Parameter recommendations and explanations
- Error handling and troubleshooting
- Security considerations and authorization checks
- Example conversations and response templates

### Configuration

Add to your Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS or `%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "boaz": {
      "command": "python3",
      "args": ["/path/to/BOAZ-MCP/boaz_mcp/server.py"],
      "env": {
        "BOAZ_PATH": "/path/to/BOAZ-MCP/BOAZ_beta",
        "BOAZ_OUTPUT_DIR": "/path/to/BOAZ-MCP/BOAZ_beta/output"
      }
    }
  }
}
```

**Replace `/path/to/BOAZ-MCP` with your actual installation directory.**

For Cursor IDE, edit `~/.cursor/mcp.json` instead.

See [mcp_config.json](mcp_config.json) for a complete example.

## Architecture

```
BOAZ-MCP/
├── BOAZ_beta/              # Core BOAZ framework
│   ├── Boaz.py            # Main entry point
│   ├── loaders/           # 77+ process injection templates
│   ├── encoders/          # Payload encoding modules
│   ├── signature/         # Binary signing utilities
│   ├── obfuscate/         # Code obfuscation tools
│   └── entropy/           # Entropy reduction modules
├── boaz_mcp/              # MCP server implementation
│   └── server.py          # MCP protocol handler
├── docs/                  # Additional documentation
├── README.md              # This file
├── INSTALL.md             # Installation guide
├── USAGE.md               # Usage examples
├── API.md                 # MCP API reference
├── AI_AGENTS.md           # AI assistant integration guide
├── setup.sh               # Automated setup script
└── mcp_config.json        # Example MCP configuration
```

## Common Workflows

### Workflow 1: Generate Evasive Beacon
```bash
# Generate Cobalt Strike beacon with advanced evasion
python3 Boaz.py \
  -f beacon.exe \
  -o evasive_beacon.exe \
  -t donut \
  -l 37 \
  -e aes \
  -c akira \
  -obf \
  -a \
  -sleep \
  -etw \
  -cfg
```

### Workflow 2: Create DLL for Side-Loading
```bash
# Generate DLL with stealth injection
python3 Boaz.py \
  -f payload.exe \
  -o sideload.dll \
  -dll \
  -l 48 \
  -e uuid \
  -c pluto \
  -obf_api \
  -dream 2000
```

### Workflow 3: Anti-Forensic Execution
```bash
# Generate payload with self-deletion and trace removal
python3 Boaz.py \
  -f implant.exe \
  -o stealth.exe \
  -l 51 \
  -e chacha \
  -d \
  -af \
  -entropy 2
```

## Supported Loaders

BOAZ provides 77+ specialized loaders for different evasion scenarios:

- **Loader 1-11**: Classic syscall variants with threadless execution
- **Loader 16-20**: Userland API injection techniques
- **Loader 22-41**: Advanced stealth injection methods
- **Loader 48-69**: Memory guard and breakpoint handlers
- **Loader 73-77**: Virtual table and JIT-based threadless injection

See [API.md](API.md#loaders) for complete loader documentation.

## Encoding Schemes

Supported payload encodings:
- UUID, XOR, MAC Address, IPv4
- Base45, Base64, Base58
- AES, AES2 (divide & conquer), DES
- ChaCha20, RC4
- ASCON (under development)

## Security Considerations

### Authorized Use Only
- Obtain written permission before testing on any system
- Use only in isolated lab environments or with explicit authorization
- Comply with all applicable laws and regulations
- Document all testing activities

### Operational Security
- Never use BOAZ on production systems without authorization
- Maintain chain of custody for generated payloads
- Use secure communication channels for payload delivery
- Implement proper access controls on BOAZ infrastructure

## Troubleshooting

### Common Issues

**Issue**: LLVM compilation fails
```bash
# Solution: Ensure LLVM is properly installed
./setup.sh  # Re-run setup
```

**Issue**: Wine execution errors
```bash
# Solution: Update Wine and configure properly
sudo dpkg --add-architecture i386
sudo apt update
sudo apt install wine wine32
```

**Issue**: MinGW not found
```bash
# Solution: Install MinGW cross-compiler
sudo apt install mingw-w64 mingw-w64-tools
```

See [INSTALL.md](INSTALL.md#troubleshooting) for more solutions.

## References

### Presentations
- [BlackHat USA 2024 - Arsenal](https://www.blackhat.com/us-24/arsenal/schedule/)
- [DEFCON 33](https://hackertracker.app/event/?conf=DEFCON33&event=61439)

### Academic Foundation
Based on multi-layered evasion concepts from:
- Swinnen & Mesbahi (2014) - "One Packer to Rule Them All" (Black Hat USA)

### Integration Projects
- [The Donut](https://github.com/TheWover/donut) - Position Independent Code generator
- [Pluto](https://github.com/bluesadi/Pluto) - LLVM obfuscation
- [Akira](https://github.com/KomiMoe/Arkari) - LLVM obfuscation
- [pe_to_shellcode](https://github.com/hasherezade/pe_to_shellcode) - PE conversion
- [Amber](https://github.com/EgeBalci/amber) - Reflective PE packer
- [Shoggoth](https://github.com/frkngksl/Shoggoth) - Shellcode encryption
- [Stardust](https://github.com/Cracked5pider/Stardust) - PIC framework

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with detailed description

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. The authors and contributors are not responsible for any misuse or damage caused by this tool. Users assume all responsibility for ensuring their activities are legal and authorized.

## Contact

- **Author**: Thomas M
- **GitHub Issues**: For bug reports and feature requests
- **Security Research**: For responsible disclosure of vulnerabilities

---

**Remember**: With great power comes great responsibility. Use BOAZ ethically and legally.
