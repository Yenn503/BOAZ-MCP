# Docker Setup for BOAZ MCP

This directory contains Docker configuration files for running BOAZ MCP without local compilation.

## Files

- **docker-compose.yml** - Docker Compose configuration for easy deployment

## Quick Start

### Option 1: Docker Compose (Recommended for persistent server)

```bash
# From BOAZ-MCP root directory
cd docker
docker-compose up -d

# Check logs
docker-compose logs -f

# Stop server
docker-compose down
```

### Option 2: Docker Run (For one-time use)

```bash
docker run --rm -it \
  -v "$PWD/../payloads:/boaz/payloads:ro" \
  -v "$PWD/../output:/boaz/output" \
  -v "$PWD/../boaz_mcp:/boaz/boaz_mcp:ro" \
  mmttxx20/boaz-builder \
  python3 /boaz/boaz_mcp/server.py
```

### Option 3: Use Configure Script (Easiest)

```bash
# From BOAZ-MCP root directory
cd install
./configure_mcp.sh
```

This will automatically set up Docker mode for your AI client.

## Prerequisites

- Docker installed and running
- 8GB RAM minimum
- 10GB free disk space

## What's Included in the Image

The `mmttxx20/boaz-builder` Docker image includes:

- Pre-compiled Akira LLVM obfuscator
- Pre-compiled Pluto LLVM obfuscator
- All BOAZ dependencies
- MingW cross-compiler
- Wine for testing
- All shellcode generators (Donut, PE2SH, etc.)
- Binary signing tools

## Volume Mounts

The Docker configuration mounts these directories:

| Host Path | Container Path | Purpose |
|-----------|---------------|---------|
| `../payloads/` | `/boaz/payloads/` | Your input payloads (read-only) |
| `../output/` | `/boaz/output/` | Generated evasive payloads |
| `../boaz_mcp/` | `/boaz/boaz_mcp/` | MCP server code (read-only) |
| `$HOME` | `/host_home/` | Optional access to your home directory (read-only) |

## Troubleshooting

### Container Won't Start

```bash
# Check Docker is running
docker ps

# Pull latest image
docker pull mmttxx20/boaz-builder:latest

# Check logs
docker logs boaz_mcp_server
```

### Permission Issues

```bash
# Fix output directory permissions
chmod -R 777 ../output/
```

### Can't Access Files

Make sure files are in the correct mounted directories:
- Input files → `payloads/`
- Check output → `output/`

## Building Custom Image (Advanced)

If you need to modify the BOAZ image:

```bash
# Create Dockerfile in this directory
# Then build:
docker build -t my-boaz:latest .

# Update docker-compose.yml to use your image
```

## Security Notes

⚠️ **Volume Mounts**: The home directory mount is read-only for safety. Remove it if not needed.

⚠️ **Network Mode**: Bridge mode by default. Change to `host` in docker-compose.yml if needed.

⚠️ **Resource Limits**: Adjust CPU/memory limits in docker-compose.yml based on your system.

## Documentation

- **Quick Start**: ../docs/DOCKER_QUICKSTART.md
- **Full Installation Guide**: ../docs/INSTALL.md
- **Usage Examples**: ../docs/USAGE.md
- **API Reference**: ../docs/API.md
- **Configuration Examples**: ../examples/mcp_config.json
