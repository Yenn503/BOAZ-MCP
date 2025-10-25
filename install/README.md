# BOAZ MCP Installation Scripts

This directory contains installation and configuration scripts for BOAZ MCP.

## Files

- **configure_mcp.sh** - Universal MCP configuration generator (works with all AI clients)
- **setup.sh** - Full installation script (compiles LLVM from source)

## Quick Setup (Docker - Recommended)

**No compilation needed! 5 minutes setup:**

```bash
# 1. Pull Docker image (from BOAZ-MCP root)
docker pull mmttxx20/boaz-builder:latest

# 2. Run configuration
./configure_mcp.sh

# 3. Restart your AI client
# Done!
```

The configure script will:
- Detect if Docker is available
- Offer Docker mode (recommended) or local mode
- Auto-configure for your AI client (Claude, Continue.dev, Cursor, etc.)
- Create necessary directories

## Full Installation (Local - Advanced)

**Compiles LLVM from source (60-90 minutes):**

```bash
./setup.sh
```

This will:
- Install all system dependencies
- Compile Akira LLVM obfuscator (~30 mins)
- Compile Pluto LLVM obfuscator (~30 mins)
- Install shellcode generators
- Install binary signing tools
- Set up Python environment
- Configure MCP server

**Requirements:**
- 8GB+ RAM (16GB recommended)
- 60-90 minutes
- 20GB+ free disk space

## Supported AI Clients

The `configure_mcp.sh` script supports:

1. **Claude Desktop** - Full automatic configuration
2. **Continue.dev** (VS Code) - Full automatic configuration
3. **Cursor IDE** - Full automatic configuration
4. **VS Code** (generic MCP) - Full automatic configuration
5. **All of the above** - Configure everything at once
6. **Manual** - Show config for copy/paste

## Usage

### Configure for Single AI Client

```bash
./configure_mcp.sh
# Select option 1-4 for your client
```

### Configure for All AI Clients

```bash
./configure_mcp.sh
# Select option 5
```

### Show Manual Configuration

```bash
./configure_mcp.sh
# Select option 6 for manual config JSON
```

## Docker vs Local Mode

The configuration script will ask which mode you prefer:

### Docker Mode (Recommended)

**Advantages:**
- ✅ No LLVM compilation (saves 60+ minutes)
- ✅ Pre-configured obfuscators
- ✅ Consistent across all systems
- ✅ No system pollution
- ✅ Easy updates

**Disadvantages:**
- ❌ Requires Docker
- ❌ ~500MB-1GB RAM overhead
- ❌ Slightly slower file I/O

### Local Mode

**Advantages:**
- ✅ Faster file access
- ✅ Can modify BOAZ code directly
- ✅ No Docker required

**Disadvantages:**
- ❌ 60-90 minute LLVM compilation
- ❌ High RAM usage during build
- ❌ System dependencies required

## Troubleshooting

### "Docker not found"

Install Docker:
```bash
# Ubuntu/Debian
sudo apt install docker.io
sudo usermod -aG docker $USER
newgrp docker
```

### "LLVM compilation failed"

If local mode fails:
1. Check you have 8GB+ RAM
2. Close other applications
3. Try Docker mode instead

### "MCP not appearing in AI client"

1. Check configuration was created:
   ```bash
   # Claude Desktop
   cat ~/.config/Claude/claude_desktop_config.json

   # Continue.dev
   cat ~/.continue/config.json
   ```

2. Ensure paths are absolute (not relative)

3. Restart AI client completely

### "Permission denied"

```bash
chmod +x configure_mcp.sh setup.sh
```

## Environment Variables

After installation, these are set:

- `BOAZ_HOME` - Points to BOAZ_beta directory
- `PATH` - Includes BOAZ directory
- `boaz` alias - Shortcut to run Boaz.py

Reload your shell:
```bash
source ~/.bashrc  # or ~/.zshrc
```

## Uninstallation

To remove BOAZ:

```bash
# Stop Docker containers (if using Docker mode)
cd ../docker
docker-compose down

# Remove BOAZ directory
cd ~
rm -rf BOAZ-MCP

# Remove MCP configurations
rm ~/.config/Claude/claude_desktop_config.json
rm ~/.continue/config.json
rm ~/.cursor/mcp_settings.json
```

## Updates

### Docker Mode

```bash
docker pull mmttxx20/boaz-builder:latest
# Restart your AI client
```

### Local Mode

```bash
cd ~/BOAZ-MCP
git pull
./install/setup.sh
```

## Documentation

- **Quick Start**: ../docs/DOCKER_QUICKSTART.md
- **Full Installation Guide**: ../docs/INSTALL.md
- **Usage Examples**: ../docs/USAGE.md
- **API Reference**: ../docs/API.md
- **Docker Setup**: ../docker/README.md
- **Configuration Examples**: ../examples/mcp_config.json

## Support

- **Issues**: https://github.com/Yenn503/BOAZ-MCP/issues
