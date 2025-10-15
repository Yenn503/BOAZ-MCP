#!/bin/bash
# BOAZ MCP Setup Script
# Automated installation and configuration for BOAZ framework with MCP integration
# Author: BOAZ Development Team
# License: MIT

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BOAZ_DIR="${SCRIPT_DIR}/BOAZ_beta"
MCP_DIR="${SCRIPT_DIR}/boaz_mcp"

# Print banner
print_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
    ╔══════════════════════════════════════════════════════╗
    ║                                                      ║
    ║        BOAZ MCP Server Setup Script                 ║
    ║        Automated Installation & Configuration       ║
    ║                                                      ║
    ╚══════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Print colored messages
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [ "$EUID" -eq 0 ]; then
        log_warning "Running as root. Some operations may behave differently."
        read -p "Continue? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Check system requirements
check_requirements() {
    log_info "Checking system requirements..."

    # Check OS
    if [[ "$OSTYPE" != "linux-gnu"* ]]; then
        log_warning "This script is designed for Linux. You're running: $OSTYPE"
        log_warning "Some features may not work correctly."
    fi

    # Check disk space (need at least 20GB for LLVM)
    available_space=$(df -BG "$SCRIPT_DIR" | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ "$available_space" -lt 20 ]; then
        log_error "Insufficient disk space. Need at least 20GB, have ${available_space}GB"
        exit 1
    fi

    # Check RAM (recommend at least 8GB)
    total_ram=$(free -g | awk 'NR==2 {print $2}')
    if [ "$total_ram" -lt 8 ]; then
        log_warning "Low RAM detected (${total_ram}GB). LLVM compilation may be slow or fail."
        log_warning "Recommend at least 8GB RAM for optimal performance."
    fi

    log_success "System requirements check passed"
}

# Update system packages
update_system() {
    log_info "Updating system packages..."

    read -p "Do you want to update and upgrade system packages? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo apt update && sudo apt upgrade -y
        log_success "System packages updated"
    else
        log_warning "Skipping system update"
    fi
}

# Install core dependencies
install_dependencies() {
    log_info "Installing core dependencies..."

    # Build essentials
    sudo apt install -y \
        build-essential \
        cmake \
        ninja-build \
        git \
        gcc \
        g++ \
        nasm \
        zlib1g-dev \
        libtinfo-dev \
        libncurses-dev

    # Cross-compilation tools
    sudo apt install -y \
        mingw-w64 \
        mingw-w64-tools \
        x86_64-w64-mingw32-g++

    # Wine for testing
    sudo dpkg --add-architecture i386 2>/dev/null || true
    sudo apt update
    sudo apt install -y wine wine32:i386 || {
        log_warning "Wine32 installation failed. Continuing without it."
    }

    # Additional tools
    sudo apt install -y \
        osslsigncode \
        python3 \
        python3-pip \
        python3-venv

    log_success "Core dependencies installed"
}

# Install Python dependencies
install_python_deps() {
    log_info "Installing Python dependencies..."

    cd "$BOAZ_DIR"

    # Install from requirements.txt if exists
    if [ -f "requirements.txt" ]; then
        pip3 install -r requirements.txt
    else
        # Install manually
        pip3 install pyinstaller cryptography base58 pyopenssl
    fi

    # Install MCP SDK
    pip3 install mcp

    log_success "Python dependencies installed"
}

# Install shellcode generators
install_shellcode_generators() {
    log_info "Installing shellcode generators..."

    cd "$BOAZ_DIR"

    # Check Donut
    if [ -f "donut" ]; then
        log_success "Donut already installed"
        chmod +x donut
    else
        log_warning "Donut not found. Please install manually from: https://github.com/TheWover/donut"
    fi

    # Check PE2SH
    if [ -f "PIC/pe2shc.exe" ]; then
        log_success "PE2SH already installed"
    else
        log_warning "PE2SH not found. Please install manually from: https://github.com/hasherezade/pe_to_shellcode"
    fi

    log_success "Shellcode generators check complete"
}

# Install binary signing tools
install_signing_tools() {
    log_info "Installing binary signing tools..."

    cd "$BOAZ_DIR"

    # Install Mangle
    if [ ! -f "signature/Mangle" ]; then
        log_info "Installing Mangle..."

        if command -v go &> /dev/null; then
            git clone https://github.com/optiv/Mangle.git /tmp/Mangle
            cd /tmp/Mangle
            go get github.com/Binject/debug/pe
            go build Mangle.go
            mkdir -p "$BOAZ_DIR/signature"
            mv Mangle "$BOAZ_DIR/signature/"
            cd "$BOAZ_DIR"
            rm -rf /tmp/Mangle
            log_success "Mangle installed"
        else
            log_warning "Go not installed. Skipping Mangle installation."
        fi
    else
        log_success "Mangle already installed"
    fi

    # Install pyMetaTwin
    if [ ! -f "signature/metatwin.py" ]; then
        log_info "Installing pyMetaTwin..."

        git clone https://github.com/thomasxm/pyMetaTwin /tmp/pyMetaTwin
        mkdir -p "$BOAZ_DIR/signature"
        cp -r /tmp/pyMetaTwin/* "$BOAZ_DIR/signature/"
        cd "$BOAZ_DIR/signature"

        if [ -f "install.sh" ]; then
            chmod +x install.sh
            sudo ./install.sh || log_warning "pyMetaTwin installation failed"
        fi

        cd "$BOAZ_DIR"
        rm -rf /tmp/pyMetaTwin
        log_success "pyMetaTwin installed"
    else
        log_success "pyMetaTwin already installed"
    fi
}

# Install SysWhispers2
install_syswhispers() {
    log_info "Installing SysWhispers2..."

    cd "$BOAZ_DIR"

    if [ ! -d "SysWhispers2" ]; then
        git clone https://github.com/jthuraisamy/SysWhispers2
        cd SysWhispers2
        python3 ./syswhispers.py --preset common -o syscalls_common
        cd "$BOAZ_DIR"
        log_success "SysWhispers2 installed"
    else
        log_success "SysWhispers2 already installed"
    fi
}

# Install LLVM obfuscators
install_llvm_obfuscators() {
    log_info "Installing LLVM obfuscators (this will take 30-60 minutes)..."

    read -p "Install LLVM obfuscators (Akira and Pluto)? This is required for advanced obfuscation. [Y/n] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        install_akira
        install_pluto
    else
        log_warning "Skipping LLVM installation. BOAZ will work without LLVM but with limited obfuscation."
    fi
}

# Install Akira obfuscator
install_akira() {
    cd "$BOAZ_DIR"

    if [ -d "akira_built" ]; then
        log_success "Akira already installed"
        return
    fi

    log_info "Installing Akira LLVM obfuscator..."

    git clone https://github.com/thomasxm/Akira-obfuscator.git
    cd Akira-obfuscator
    mkdir -p akira_built
    cd akira_built

    # Configure
    cmake \
        -DCMAKE_CXX_FLAGS="" \
        -DCMAKE_BUILD_TYPE=Release \
        -DLLVM_ENABLE_ASSERTIONS=ON \
        -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra;lld;lldb" \
        -G "Ninja" \
        ../llvm

    # Build (use fewer jobs if low on RAM)
    local jobs=$(nproc)
    if [ "$total_ram" -lt 16 ]; then
        jobs=2
        log_warning "Using 2 parallel jobs due to RAM constraints"
    fi

    ninja -j"$jobs" || {
        log_error "Akira compilation failed"
        cd "$BOAZ_DIR"
        rm -rf Akira-obfuscator
        return 1
    }

    # Move to BOAZ directory
    cd "$BOAZ_DIR"
    mv Akira-obfuscator/akira_built ./
    rm -rf Akira-obfuscator

    log_success "Akira installed successfully"

    # Test Akira
    test_akira
}

# Install Pluto obfuscator
install_pluto() {
    cd "$BOAZ_DIR"

    if [ -d "llvm_obfuscator_pluto" ]; then
        log_success "Pluto already installed"
        return
    fi

    log_info "Installing Pluto LLVM obfuscator..."

    git clone https://github.com/thomasxm/Pluto.git
    cd Pluto
    mkdir -p pluto_build
    cd pluto_build

    # Configure and build
    cmake -G Ninja \
        -S .. \
        -B build \
        -DCMAKE_C_COMPILER="gcc" \
        -DCMAKE_CXX_COMPILER="g++" \
        -DCMAKE_INSTALL_PREFIX="../llvm_obfuscator_pluto/" \
        -DCMAKE_BUILD_TYPE=Release

    local jobs=$(nproc)
    if [ "$total_ram" -lt 16 ]; then
        jobs=2
    fi

    ninja -j"$jobs" -C build install || {
        log_error "Pluto compilation failed"
        cd "$BOAZ_DIR"
        rm -rf Pluto
        return 1
    }

    # Move to BOAZ directory
    cd "$BOAZ_DIR"
    mkdir -p llvm_obfuscator_pluto
    mv Pluto/pluto_build/install/* llvm_obfuscator_pluto/
    rm -rf Pluto

    log_success "Pluto installed successfully"

    # Test Pluto
    test_pluto
}

# Test Akira installation
test_akira() {
    log_info "Testing Akira installation..."

    cd "$BOAZ_DIR"

    # Detect MinGW version
    local GCCVER=$(ls /usr/lib/gcc/x86_64-w64-mingw32 2>/dev/null | grep -E 'posix|win32' | sort -V | tail -n 1)

    if [ -z "$GCCVER" ]; then
        log_warning "MinGW version not detected. Skipping Akira test."
        return
    fi

    if [ ! -f "loader2_test.c" ]; then
        log_warning "Test file not found. Skipping Akira test."
        return
    fi

    ./akira_built/bin/clang++ \
        -D nullptr=NULL \
        -mllvm -irobf-indbr -mllvm -irobf-icall \
        -target x86_64-w64-windows-gnu \
        loader2_test.c classic_stubs/syscalls.c classic_stubs/syscallsstubs.std.x64.s \
        -o test_akira.exe \
        -L/usr/lib/gcc/x86_64-w64-mingw32/$GCCVER \
        -L/usr/x86_64-w64-mingw32/lib \
        -lstdc++ -lgcc_s -lgcc -lws2_32 -lpsapi 2>/dev/null || {
        log_warning "Akira test compilation failed"
        return
    }

    if [ -f "test_akira.exe" ]; then
        wine test_akira.exe &>/dev/null && log_success "Akira test passed" || log_warning "Akira test execution failed (Wine issue?)"
        rm -f test_akira.exe
    fi
}

# Test Pluto installation
test_pluto() {
    log_info "Testing Pluto installation..."

    cd "$BOAZ_DIR"

    local GCCVER=$(ls /usr/lib/gcc/x86_64-w64-mingw32 2>/dev/null | grep -E 'posix|win32' | sort -V | tail -n 1)

    if [ -z "$GCCVER" ]; then
        log_warning "MinGW version not detected. Skipping Pluto test."
        return
    fi

    if [ ! -f "loader2_test.c" ]; then
        log_warning "Test file not found. Skipping Pluto test."
        return
    fi

    ./llvm_obfuscator_pluto/bin/clang++ \
        -D nullptr=NULL \
        -O2 -flto -fuse-ld=lld \
        -mllvm -passes=mba,sub,bcf \
        -target x86_64-w64-mingw32 \
        loader2_test.c classic_stubs/syscalls.c classic_stubs/syscallsstubs.std.x64.s \
        -o test_pluto.exe \
        -L/usr/lib/gcc/x86_64-w64-mingw32/$GCCVER \
        -lstdc++ -lgcc_s -lgcc -lws2_32 -lpsapi 2>/dev/null || {
        log_warning "Pluto test compilation failed"
        return
    }

    if [ -f "test_pluto.exe" ]; then
        wine test_pluto.exe &>/dev/null && log_success "Pluto test passed" || log_warning "Pluto test execution failed (Wine issue?)"
        rm -f test_pluto.exe
    fi
}

# Build BOAZ executable
build_boaz_executable() {
    log_info "Building BOAZ executable..."

    cd "$BOAZ_DIR"

    if ! command -v pyinstaller &> /dev/null; then
        pip3 install pyinstaller
    fi

    pyinstaller --onefile Boaz.py || {
        log_warning "PyInstaller build failed. You can still use: python3 Boaz.py"
        return
    }

    if [ -f "dist/Boaz" ]; then
        mv dist/Boaz ./
        rm -rf dist build Boaz.spec
        chmod +x Boaz
        log_success "BOAZ executable built successfully"
    fi
}

# Setup MCP server
setup_mcp_server() {
    log_info "Setting up MCP server..."

    # Create MCP directory if it doesn't exist
    mkdir -p "$MCP_DIR"

    # Copy server script from API.md if not exists
    if [ ! -f "$MCP_DIR/server.py" ]; then
        log_info "Creating MCP server script..."

        # The server.py content is in API.md, but for this setup we'll create a minimal version
        cat > "$MCP_DIR/server.py" << 'MEOF'
#!/usr/bin/env python3
"""
BOAZ MCP Server
Minimal implementation - see API.md for full version
"""

import sys
import os

# Add BOAZ path to Python path
boaz_path = os.getenv("BOAZ_PATH")
if not boaz_path:
    print("Error: BOAZ_PATH environment variable not set", file=sys.stderr)
    sys.exit(1)

sys.path.insert(0, boaz_path)

print(f"BOAZ MCP Server starting... (BOAZ_PATH: {boaz_path})", file=sys.stderr)
print("Please implement full server from API.md", file=sys.stderr)

# Placeholder - implement full server from API.md
if __name__ == "__main__":
    print("MCP server ready. Implement full version from API.md")
MEOF

        chmod +x "$MCP_DIR/server.py"
        log_warning "MCP server template created. Please implement full version from API.md"
    else
        log_success "MCP server script already exists"
    fi

    log_success "MCP server setup complete"
}

# Create output directory
create_output_dir() {
    log_info "Creating output directory..."

    cd "$BOAZ_DIR"
    mkdir -p output

    log_success "Output directory created at $BOAZ_DIR/output"
}

# Setup environment variables
setup_environment() {
    log_info "Setting up environment variables..."

    local shell_rc=""
    if [ -n "$BASH_VERSION" ]; then
        shell_rc="$HOME/.bashrc"
    elif [ -n "$ZSH_VERSION" ]; then
        shell_rc="$HOME/.zshrc"
    else
        log_warning "Unknown shell. Please add environment variables manually."
        return
    fi

    # Check if already added
    if grep -q "BOAZ_HOME" "$shell_rc" 2>/dev/null; then
        log_success "Environment variables already configured"
        return
    fi

    log_info "Adding BOAZ environment variables to $shell_rc"

    cat >> "$shell_rc" << EOF

# BOAZ MCP Configuration
export BOAZ_HOME="$BOAZ_DIR"
export PATH="\$BOAZ_HOME:\$PATH"

# Alias for convenience
alias boaz="python3 \$BOAZ_HOME/Boaz.py"
EOF

    log_success "Environment variables added. Run: source $shell_rc"
}

# Print MCP configuration instructions
print_mcp_config() {
    log_info "MCP Configuration Instructions"
    echo
    echo -e "${CYAN}To configure Claude Desktop, add this to your configuration file:${NC}"
    echo
    echo "macOS: ~/Library/Application Support/Claude/claude_desktop_config.json"
    echo "Linux: ~/.config/Claude/claude_desktop_config.json"
    echo
    echo -e "${GREEN}Configuration:${NC}"
    cat << EOF
{
  "mcpServers": {
    "boaz": {
      "command": "python3",
      "args": ["$MCP_DIR/server.py"],
      "env": {
        "BOAZ_PATH": "$BOAZ_DIR"
      }
    }
  }
}
EOF
    echo
}

# Print completion message
print_completion() {
    echo
    echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                      ║${NC}"
    echo -e "${GREEN}║        BOAZ MCP Installation Complete!              ║${NC}"
    echo -e "${GREEN}║                                                      ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
    echo
    log_success "Installation directory: $SCRIPT_DIR"
    log_success "BOAZ framework: $BOAZ_DIR"
    log_success "MCP server: $MCP_DIR"
    echo
    log_info "Next steps:"
    echo "  1. Review the MCP configuration above"
    echo "  2. Add configuration to Claude Desktop"
    echo "  3. Implement full MCP server from API.md"
    echo "  4. Restart Claude Desktop"
    echo "  5. Test with: python3 Boaz.py -h"
    echo
    log_info "Documentation:"
    echo "  - README.md  : Overview and quick start"
    echo "  - INSTALL.md : Detailed installation guide"
    echo "  - USAGE.md   : Usage examples and workflows"
    echo "  - API.md     : Complete MCP API reference"
    echo
    log_warning "Remember: This tool is for authorized security testing only!"
    echo
}

# Main installation flow
main() {
    print_banner

    check_root
    check_requirements
    update_system

    install_dependencies
    install_python_deps
    install_shellcode_generators
    install_signing_tools
    install_syswhispers
    install_llvm_obfuscators

    build_boaz_executable
    setup_mcp_server
    create_output_dir
    setup_environment

    print_mcp_config
    print_completion
}

# Run main installation
main "$@"
