#!/bin/bash

# BOAZ-MCP Quick Start Launcher
# Automatically sets up BOAZ-MCP with Docker for your AI client

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Banner
echo ""
echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   BOAZ-MCP Quick Start Launcher       ║${NC}"
echo -e "${BLUE}║   Get started in 5 minutes!           ║${NC}"
echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo ""

# Check if Docker is installed
print_info "Checking Docker installation..."
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed!"
    echo ""
    echo "Please install Docker first:"
    echo "  Ubuntu/Debian: sudo apt install docker.io"
    echo "  Fedora: sudo dnf install docker"
    echo "  macOS: Install Docker Desktop from docker.com"
    echo ""
    exit 1
fi
print_success "Docker is installed"

# Check if Docker is running
print_info "Checking if Docker is running..."
if ! docker ps &> /dev/null; then
    print_error "Docker is not running!"
    echo ""
    echo "Please start Docker:"
    echo "  Linux: sudo systemctl start docker"
    echo "  macOS/Windows: Start Docker Desktop"
    echo ""
    exit 1
fi
print_success "Docker is running"

# Pull Docker image
print_info "Pulling BOAZ Docker image (includes pre-compiled LLVM obfuscators)..."
if docker pull mmttxx20/boaz-builder:latest; then
    print_success "Docker image pulled successfully"
else
    print_error "Failed to pull Docker image"
    exit 1
fi

# Create necessary directories
print_info "Creating necessary directories..."
mkdir -p payloads output
chmod 777 output
print_success "Directories created: payloads/ and output/"

# Run the configuration script
print_info "Launching MCP configuration wizard..."
echo ""
chmod +x install/configure_mcp.sh
./install/configure_mcp.sh

# Final instructions
echo ""
echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Setup Complete!                      ║${NC}"
echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo ""
print_success "BOAZ-MCP is ready to use!"
echo ""
echo "Next steps:"
echo "  1. Restart your AI client completely"
echo "  2. BOAZ tools should now appear in your MCP client"
echo "  3. Try: 'List available BOAZ loaders' to verify"
echo ""
echo "File locations:"
echo "  • Place your payloads in: ${BLUE}./payloads/${NC}"
echo "  • Generated files appear in: ${BLUE}./output/${NC}"
echo ""
echo "Documentation:"
echo "  • Quick Start Guide: ${BLUE}DOCKER_QUICKSTART.md${NC}"
echo "  • Docker Setup: ${BLUE}docker/README.md${NC}"
echo "  • Installation: ${BLUE}install/README.md${NC}"
echo ""
echo -e "${YELLOW}⚠️  Remember: BOAZ wraps existing payloads with evasion techniques.${NC}"
echo -e "${YELLOW}   You must provide your own payloads (or use notepad.exe for testing).${NC}"
echo ""
