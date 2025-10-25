# BOAZ MCP - Docker Quick Start Guide

**No compilation needed! Get started in 5 minutes.**

This guide helps you set up BOAZ MCP using Docker, avoiding the 30-60 minute LLVM compilation process.

## Prerequisites

- Docker installed and running
- 8GB RAM minimum
- 10GB free disk space
- An MCP-compatible AI client (Claude Desktop, Continue.dev, Cursor, etc.)

## Quick Setup (5 Minutes)

### Step 1: Clone Repository

```bash
git clone https://github.com/Yenn503/BOAZ-MCP.git
cd BOAZ-MCP
```

### Step 2: Pull Docker Image

```bash
# Pull the pre-compiled BOAZ image (includes Akira & Pluto LLVM obfuscators)
docker pull mmttxx20/boaz-builder:latest

# Verify the image
docker images | grep boaz-builder
```

### Step 3: Create Required Directories

```bash
# Create directories for payloads and output
mkdir -p payloads output

# Copy a test payload (or use your own)
# For testing, you can use any Windows PE file
cp /path/to/your/payload.exe payloads/
```

### Step 4: Configure Your AI Client

Run the automatic configuration script:

```bash
chmod +x install/configure_mcp.sh
./install/configure_mcp.sh
```

Select your AI client:
- Option 1: Claude Desktop
- Option 2: Continue.dev (VS Code)
- Option 3: Cursor IDE
- Option 4: VS Code (generic MCP)
- Option 5: All of the above

The script will:
1. Detect Docker availability
2. Create proper MCP configuration
3. Set up volume mounts for payloads and output

### Step 5: Restart Your AI Client

- **Claude Desktop**: Quit completely and reopen
- **Continue.dev**: Reload VS Code window (Cmd/Ctrl+Shift+P → "Reload Window")
- **Cursor**: Restart the IDE
- **VS Code**: Reload window

### Step 6: Verify BOAZ is Connected

In your AI client, try:
```
"List available BOAZ loaders"
```

You should see the 77 available process injection loaders.

## Usage Examples

### Basic Payload Wrapping

```
"I have beacon.exe in my payloads directory.
Wrap it with UUID encoding and loader 16 (basic stealth).
Output to: evasive_beacon.exe"
```

### Advanced EDR Bypass

```
"I have mimikatz.exe in payloads/.
Create an EDR bypass version with:
- Loader 51 (memory guard)
- AES encryption
- Akira obfuscation
- ETW patching
- Anti-emulation
Output: mimikatz_evasive.exe"
```

### List Available Tools

```
"Show me all threadless injection loaders"
"What encoders are available?"
"Analyze the entropy of my payload at payloads/test.exe"
```

## File Locations

When using Docker mode:

**Input (your payloads):**
```
BOAZ-MCP/payloads/
  ├── beacon.exe          ← Place your payloads here
  ├── mimikatz.exe
  └── meterpreter.exe
```

**Output (generated files):**
```
BOAZ-MCP/output/
  ├── evasive_beacon.exe  ← Generated payloads appear here
  ├── mimikatz_evasive.exe
  └── analysis_report.txt
```

**Access from host:**
- Input: `./payloads/your_payload.exe`
- Output: `./output/generated_file.exe`

## Troubleshooting

### "BOAZ not showing up in my AI client"

1. Verify Docker is running:
   ```bash
   docker ps
   ```

2. Test Docker image manually:
   ```bash
   docker run --rm -it mmttxx20/boaz-builder python3 /boaz/BOAZ_beta/Boaz.py -h
   ```

3. Check MCP configuration:
   ```bash
   # Claude Desktop
   cat ~/.config/Claude/claude_desktop_config.json

   # Continue.dev
   cat ~/.continue/config.json
   ```

4. Restart AI client completely (not just reload)

### "Permission denied on output directory"

```bash
chmod 777 output/
```

### "Docker image pull fails"

Try with sudo:
```bash
sudo docker pull mmttxx20/boaz-builder:latest
```

Or add yourself to docker group:
```bash
sudo usermod -aG docker $USER
newgrp docker
```

### "MCP server not responding"

Check Docker logs:
```bash
docker logs boaz_mcp_server
```

### "File not found in container"

Remember paths inside container are different:
- Host: `./payloads/beacon.exe`
- Container: `/boaz/payloads/beacon.exe`

The MCP server automatically handles this mapping, so just refer to files as:
```
"Use payloads/beacon.exe as input"
```

## Alternative: Docker Compose

For persistent server mode:

```bash
# Start BOAZ MCP server
docker-compose up -d

# Check logs
docker-compose logs -f

# Stop server
docker-compose down
```

## Manual Configuration

If the auto-configurator doesn't work, manually add this to your MCP config:

### Claude Desktop

Location: `~/.config/Claude/claude_desktop_config.json` (Linux) or `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)

```json
{
  "mcpServers": {
    "boaz": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "/absolute/path/to/BOAZ-MCP/payloads:/boaz/payloads:ro",
        "-v", "/absolute/path/to/BOAZ-MCP/output:/boaz/output",
        "-v", "/absolute/path/to/BOAZ-MCP/boaz_mcp:/boaz/boaz_mcp:ro",
        "mmttxx20/boaz-builder",
        "python3", "/boaz/boaz_mcp/server.py"
      ],
      "env": {
        "BOAZ_PATH": "/boaz/BOAZ_beta"
      }
    }
  }
}
```

**Important**: Replace `/absolute/path/to/BOAZ-MCP` with your actual path!

### Continue.dev

Location: `~/.continue/config.json`

Add the same configuration as above to your Continue.dev config file.

### Cursor

Location: `~/.cursor/mcp_settings.json`

Use the same Docker configuration as Claude Desktop.

## Advantages of Docker Mode

✅ **No LLVM compilation** - Skip the 30-60 minute build process
✅ **Pre-configured** - Akira & Pluto obfuscators already built
✅ **Consistent** - Works the same on all systems
✅ **Isolated** - Doesn't mess with your system
✅ **Easy updates** - Just pull latest image

## Disadvantages

❌ Docker overhead (~500MB-1GB RAM)
❌ Slightly slower file I/O through volumes
❌ Requires Docker to be installed

## Next Steps

- Read [USAGE.md](USAGE.md) for detailed examples
- Check [API.md](API.md) for all available MCP tools
- Review [AI_AGENTS.md](AI_AGENTS.md) for AI assistant guidance

## Security Notice

⚠️ **BOAZ is for authorized security testing only**

- Obtain written permission before use
- Use in isolated environments
- Document all activities
- Comply with applicable laws

## Support

- **Issues**: https://github.com/Yenn503/BOAZ-MCP/issues
- **Original BOAZ**: https://github.com/thomasxm/Boaz_beta
- **MCP Protocol**: https://modelcontextprotocol.io

---

**No malware included** - BOAZ wraps your existing payloads with evasion techniques. You must provide your own test payloads (or use the included notepad.exe for testing).
