<div align="center">
  <img src="BOAZ-MCP.png" alt="BOAZ MCP Logo" width="300">
</div>

# BOAZ-MCP

**AI-Powered Evasion Framework for Authorized Red Team Operations**

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://www.linux.org/)

> ⚠️ **For authorized security testing only.** Obtain written permission before use.

---

## What is BOAZ-MCP?

BOAZ-MCP wraps the [BOAZ framework](https://github.com/thomasxm/Boaz_beta) with MCP (Model Context Protocol), enabling AI assistants to generate evasive payloads through natural language.

**Key Features:**
- 77+ process injection loaders
- 12 encoding schemes (AES, ChaCha20, UUID, XOR, etc.)
- LLVM obfuscation (Akira & Pluto)
- Syscalls, API unhooking, ETW patching
- Anti-emulation, sleep obfuscation

**Important:** BOAZ wraps your existing payloads (Cobalt Strike, Mimikatz, etc.) with evasion techniques. You must provide your own payloads.

---

## Quick Start

### Docker Setup (5 Minutes) - Recommended

```bash
git clone https://github.com/Yenn503/BOAZ-MCP.git
cd BOAZ-MCP
./quickstart.sh
```

✅ No compilation needed • Pre-built obfuscators • Works everywhere

### Manual Setup (60-90 Minutes)

```bash
git clone https://github.com/Yenn503/BOAZ-MCP.git
cd BOAZ-MCP
./install/setup.sh
```

Compiles Akira & Pluto LLVM obfuscators locally. Requires: Linux, 8GB+ RAM, build tools.

**Detailed guides:** [docs/DOCKER_QUICKSTART.md](docs/DOCKER_QUICKSTART.md) | [docs/INSTALL.md](docs/INSTALL.md)

---

## Supported AI Clients

**Auto-configuration available for:**
- Claude Desktop
- Claude Code CLI
- Continue.dev (VS Code)
- Cursor IDE
- VS Code (Generic MCP)

**Run configurator:**
```bash
./install/configure_mcp.sh
```

**Manual configuration:** See [Configuration Guide](docs/INSTALL.md#manual-configuration)

---

## Usage Examples

Talk to your AI assistant naturally:

```
"I have beacon.exe. Make it evasive with UUID encoding and loader 16."
```

```
"Wrap mimikatz.exe with Akira obfuscation and ETW patching."
```

```
"Show me all threadless injection loaders."
```

**More examples:** [docs/USAGE.md](docs/USAGE.md)

---

## Documentation

| Document | Description |
|----------|-------------|
| [DOCKER_QUICKSTART.md](docs/DOCKER_QUICKSTART.md) | Docker setup guide |
| [INSTALL.md](docs/INSTALL.md) | Detailed installation |
| [USAGE.md](docs/USAGE.md) | Usage examples |
| [API.md](docs/API.md) | MCP tools reference |
| [AI_AGENTS.md](docs/AI_AGENTS.md) | AI assistant guide |

---

## File Locations

After setup:
- **Input:** Place payloads in `payloads/`
- **Output:** Find generated files in `output/`

---

## Repository Structure

```
BOAZ-MCP/
├── quickstart.sh          # One-command setup
├── docs/                  # All documentation
├── examples/              # Configuration examples
├── install/               # Installation scripts
├── docker/                # Docker setup
├── tests/                 # Test suite
├── boaz_mcp/             # MCP server
└── BOAZ_beta/            # Core BOAZ framework
```

---

## Security & Legal

**This tool is for authorized security testing only.**

✅ **You MUST:**
- Obtain written permission before use
- Use in isolated environments only
- Document all testing activities
- Comply with applicable laws

❌ **You MUST NOT:**
- Use without authorization
- Use on production systems
- Use for malicious purposes

---

## Support

- **Issues:** [GitHub Issues](https://github.com/Yenn503/BOAZ-MCP/issues)
- **Original BOAZ:** [thomasxm/Boaz_beta](https://github.com/thomasxm/Boaz_beta)
- **MCP Protocol:** [modelcontextprotocol.io](https://modelcontextprotocol.io)

---

## License

MIT License - See [LICENSE](LICENSE) for details.

**Disclaimer:** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. Users assume all responsibility for legal compliance.
