# BOAZ MCP Installation Guide

Complete installation instructions for the BOAZ MCP server and framework.

## Table of Contents

- [System Requirements](#system-requirements)
- [Quick Installation](#quick-installation)
- [Manual Installation](#manual-installation)
- [Docker Installation](#docker-installation)
- [MCP Server Setup](#mcp-server-setup)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)
- [Platform-Specific Notes](#platform-specific-notes)

## System Requirements

### Minimum Requirements
- **OS**: Linux (Debian/Ubuntu/Kali recommended)
- **CPU**: x86_64 architecture
- **RAM**: 4GB minimum, 8GB recommended
- **Disk**: 10GB free space (20GB for LLVM compilation)
- **Python**: 3.8 or higher
- **Wine**: For Windows cross-compilation testing

### Recommended Setup
- **OS**: Kali Linux 2024+ or Ubuntu 22.04+
- **CPU**: Multi-core processor (LLVM compilation is CPU-intensive)
- **RAM**: 16GB for optimal LLVM builds
- **Disk**: SSD with 30GB+ free space

## Quick Installation

The fastest way to get started is using the automated setup script:

```bash
# Clone the repository
git clone <repository-url>
cd BOAZ-MCP

# Make setup script executable
chmod +x setup.sh

# Run automated installation
./setup.sh
```

This will install:
- All system dependencies
- Python packages
- LLVM obfuscators (Pluto and Akira)
- Shellcode generators (Donut, PE2SH, etc.)
- Binary signing tools
- MCP server dependencies

**Note**: LLVM compilation takes 30-60 minutes depending on your system.

## Manual Installation

### Step 1: Update System Packages

```bash
sudo apt update && sudo apt upgrade -y
```

### Step 2: Install Core Dependencies

```bash
# Build essentials
sudo apt install -y build-essential cmake ninja-build git

# Compilers and tools
sudo apt install -y gcc g++ nasm mingw-w64 mingw-w64-tools

# Cross-compilation support
sudo apt install -y x86_64-w64-mingw32-g++

# Wine for testing
sudo apt install -y wine wine32
sudo dpkg --add-architecture i386
sudo apt install -y wine32:i386

# Additional tools
sudo apt install -y zlib1g-dev osslsigncode
```

### Step 3: Install Python Dependencies

```bash
cd BOAZ-MCP/BOAZ_beta

# Install Python packages
pip3 install -r requirements.txt

# Or install individually
pip3 install pyinstaller cryptography base58 pyopenssl
```

### Step 4: Install Shellcode Generators

#### Donut
```bash
cd BOAZ_beta
# Donut binary should be included in the repository
# If not, download from: https://github.com/TheWover/donut
chmod +x donut
```

#### PE2SH
```bash
# PE2SH should be included at PIC/pe2shc.exe
# If not, download from: https://github.com/hasherezade/pe_to_shellcode
```

### Step 5: Install Binary Signing Tools

#### Mangle
```bash
cd BOAZ_beta

# Clone and build Mangle
git clone https://github.com/optiv/Mangle.git
cd Mangle
go get github.com/Binject/debug/pe
go build Mangle.go
mv Mangle ../signature/
cd .. && rm -rf Mangle
```

#### pyMetaTwin
```bash
cd BOAZ_beta

# Clone pyMetaTwin
git clone https://github.com/thomasxm/pyMetaTwin
cp -r pyMetaTwin/* signature/
cd signature

# Install dependencies
chmod +x install.sh
sudo ./install.sh
cd ..
```

### Step 6: Install SysWhispers2

```bash
cd BOAZ_beta

# Clone SysWhispers2
git clone https://github.com/jthuraisamy/SysWhispers2
cd SysWhispers2

# Generate common syscall stubs
python3 ./syswhispers.py --preset common -o syscalls_common
cd ..
```

### Step 7: Install LLVM Obfuscators

#### Akira Obfuscator

```bash
cd BOAZ_beta

# Clone Akira
git clone https://github.com/thomasxm/Akira-obfuscator.git
cd Akira-obfuscator

# Create build directory
mkdir -p akira_built
cd akira_built

# Configure with CMake
cmake -DCMAKE_CXX_FLAGS="" \
      -DCMAKE_BUILD_TYPE=Release \
      -DLLVM_ENABLE_ASSERTIONS=ON \
      -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra;lld;lldb" \
      -G "Ninja" \
      ../llvm

# Build (this takes 30-60 minutes)
ninja -j$(nproc)

# Move to BOAZ directory
cd ../..
mv Akira-obfuscator/akira_built ./
rm -rf Akira-obfuscator
```

#### Pluto Obfuscator

```bash
cd BOAZ_beta

# Clone Pluto
git clone https://github.com/thomasxm/Pluto.git
cd Pluto

# Create build directory
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

# Build and install
ninja -j$(nproc) -C build install

# Move to BOAZ directory
cd ../..
mkdir -p llvm_obfuscator_pluto
mv Pluto/pluto_build/install/* llvm_obfuscator_pluto/
rm -rf Pluto
```

### Step 8: Verify LLVM Installations

#### Test Akira

```bash
cd BOAZ_beta

# Detect MinGW version
GCCVER=$(ls /usr/lib/gcc/x86_64-w64-mingw32 | grep -E 'posix|win32' | sort -V | tail -n 1)

# Compile test
./akira_built/bin/clang++ \
  -D nullptr=NULL \
  -mllvm -irobf-indbr -mllvm -irobf-icall \
  -target x86_64-w64-windows-gnu \
  loader2_test.c classic_stubs/syscalls.c classic_stubs/syscallsstubs.std.x64.s \
  -o test_akira.exe \
  -L/usr/lib/gcc/x86_64-w64-mingw32/$GCCVER \
  -L/usr/x86_64-w64-mingw32/lib \
  -lstdc++ -lgcc_s -lgcc -lws2_32 -lpsapi

# Test with Wine
wine test_akira.exe
```

#### Test Pluto

```bash
cd BOAZ_beta

./llvm_obfuscator_pluto/bin/clang++ \
  -D nullptr=NULL \
  -O2 -flto -fuse-ld=lld \
  -mllvm -passes=mba,sub,idc,bcf,fla,gle \
  -target x86_64-w64-mingw32 \
  loader2_test.c classic_stubs/syscalls.c classic_stubs/syscallsstubs.std.x64.s \
  -o test_pluto.exe \
  -L/usr/lib/gcc/x86_64-w64-mingw32/$GCCVER \
  -lstdc++ -lgcc_s -lgcc -lws2_32 -lpsapi

# Test with Wine
wine test_pluto.exe
```

### Step 9: Build BOAZ Executable (Optional)

```bash
cd BOAZ_beta

# Install PyInstaller if not already installed
pip3 install pyinstaller

# Build single executable
pyinstaller --onefile Boaz.py

# Move executable
mv dist/Boaz ./
rm -rf dist build Boaz.spec
```

## Docker Installation

For a containerized environment without dependency management:

### Step 1: Install Docker

```bash
# Install Docker
sudo apt install docker.io docker-cli -y

# Add user to docker group (optional)
sudo usermod -aG docker $USER
newgrp docker
```

### Step 2: Pull BOAZ Image

```bash
# Pull official BOAZ Docker image
sudo docker pull mmttxx20/boaz-builder:latest

# Verify image
sudo docker images | grep boaz
```

### Step 3: Run BOAZ Container

```bash
# Run interactive container
sudo docker run --rm -it \
  --entrypoint /bin/bash \
  -v "$HOME:/host_home" \
  -v "$PWD:/boaz/output" \
  --shm-size=1024M \
  --name boaz_container \
  mmttxx20/boaz-builder
```

### Step 4: Test in Container

```bash
# Inside container
python3 Boaz.py -h

# Generate test payload
python3 Boaz.py \
  -f /host_home/test_payload.exe \
  -o /boaz/output/output.exe \
  -t donut -l 16 -e uuid -c akira
```

Files created in `/boaz/output` will appear in your host's `$PWD` directory.

## MCP Server Setup

### Step 1: Install MCP Python SDK

```bash
# Install MCP SDK
pip3 install mcp

# Verify installation
python3 -c "import mcp; print(mcp.__version__)"
```

### Step 2: Create MCP Server Script

The MCP server script should be created at `boaz_mcp/server.py`. See [API.md](API.md) for the server implementation.

### Step 3: Configure Claude Desktop

#### macOS
```bash
# Open configuration file
nano ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

#### Linux
```bash
# Open configuration file
nano ~/.config/Claude/claude_desktop_config.json
```

Add the BOAZ server configuration:

```json
{
  "mcpServers": {
    "boaz": {
      "command": "python3",
      "args": ["/full/path/to/BOAZ-MCP/boaz_mcp/server.py"],
      "env": {
        "BOAZ_PATH": "/full/path/to/BOAZ-MCP/BOAZ_beta"
      }
    }
  }
}
```

### Step 4: Restart Claude Desktop

```bash
# Kill Claude Desktop process
killall Claude

# Or on macOS
osascript -e 'quit app "Claude"'

# Restart Claude Desktop from Applications
```

## Verification

### Verify Core Installation

```bash
cd BOAZ-MCP/BOAZ_beta

# Test basic functionality
python3 Boaz.py -h

# Test with sample payload (if available)
python3 Boaz.py -f /bin/ls -o test_output.exe -t donut
```

### Verify LLVM Obfuscators

```bash
# Check Akira
ls -la akira_built/bin/clang++

# Check Pluto
ls -la llvm_obfuscator_pluto/bin/clang++
```

### Verify MCP Server

```bash
# Test MCP server
cd boaz_mcp
python3 server.py --test

# Or check if server is recognized in Claude Desktop
# Look for "boaz" in the MCP servers list
```

### Run Integration Test

```bash
cd BOAZ_beta

# Full integration test with all features
python3 Boaz.py \
  -f /usr/bin/calc \
  -o integration_test.exe \
  -t donut \
  -l 16 \
  -e uuid \
  -c akira \
  -obf \
  -a \
  -sleep
```

## Troubleshooting

### Issue: LLVM Compilation Fails

**Symptoms**: CMake or Ninja errors during LLVM build

**Solutions**:
```bash
# Ensure sufficient RAM (8GB+ required)
free -h

# Reduce parallel jobs if low on RAM
ninja -j2  # Instead of ninja -j$(nproc)

# Install missing dependencies
sudo apt install -y libtinfo-dev libncurses-dev
```

### Issue: MinGW Not Found

**Symptoms**: Error about missing x86_64-w64-mingw32-g++

**Solutions**:
```bash
# Install MinGW
sudo apt install mingw-w64 mingw-w64-tools x86_64-w64-mingw32-g++

# Verify installation
which x86_64-w64-mingw32-g++

# Check library path
ls /usr/lib/gcc/x86_64-w64-mingw32/
```

### Issue: Wine Execution Errors

**Symptoms**: "wine: Bad EXE format" or similar

**Solutions**:
```bash
# Install 32-bit Wine support
sudo dpkg --add-architecture i386
sudo apt update
sudo apt install wine32:i386

# Reinitialize Wine
rm -rf ~/.wine
winecfg
```

### Issue: Python Package Conflicts

**Symptoms**: Import errors or version conflicts

**Solutions**:
```bash
# Use virtual environment
python3 -m venv boaz_env
source boaz_env/bin/activate
pip3 install -r requirements.txt

# Or upgrade all packages
pip3 install --upgrade -r requirements.txt
```

### Issue: Donut Not Found

**Symptoms**: "donut: command not found"

**Solutions**:
```bash
cd BOAZ_beta

# Make donut executable
chmod +x donut

# Or rebuild from source
git clone https://github.com/TheWover/donut.git
cd donut
make
cp donut ../
```

### Issue: MCP Server Not Recognized

**Symptoms**: BOAZ tools not available in Claude Desktop

**Solutions**:
```bash
# Verify MCP configuration path
cat ~/Library/Application\ Support/Claude/claude_desktop_config.json

# Check Python path
which python3

# Test server manually
cd boaz_mcp
python3 server.py

# Check logs
tail -f ~/Library/Logs/Claude/mcp*.log
```

### Issue: Permission Denied Errors

**Symptoms**: "Permission denied" when running scripts

**Solutions**:
```bash
# Make scripts executable
chmod +x setup.sh
chmod +x BOAZ_beta/donut
chmod +x signature/Mangle

# Fix ownership if needed
sudo chown -R $USER:$USER BOAZ-MCP/
```

## Platform-Specific Notes

### Kali Linux

Kali comes with many tools pre-installed:

```bash
# Update Kali
sudo apt update && sudo apt full-upgrade -y

# Install missing packages only
sudo apt install -y cmake ninja-build mingw-w64 wine
```

### Ubuntu/Debian

```bash
# Enable universe repository
sudo add-apt-repository universe
sudo apt update

# Install all dependencies
sudo apt install -y build-essential cmake ninja-build git \
                    gcc g++ mingw-w64 wine python3-pip
```

### Arch Linux

```bash
# Install dependencies
sudo pacman -S base-devel cmake ninja git mingw-w64-gcc wine python-pip

# Install Python packages
pip3 install --user -r requirements.txt
```

### WSL2 (Windows Subsystem for Linux)

BOAZ can run in WSL2, but with limitations:

```bash
# Install WSL2 Ubuntu
wsl --install -d Ubuntu-22.04

# Inside WSL, follow Ubuntu installation steps
# Note: Wine may have issues in WSL2

# Alternative: Use Docker in WSL2
sudo docker pull mmttxx20/boaz-builder:latest
```

## Post-Installation

### Set Environment Variables

Add to `~/.bashrc` or `~/.zshrc`:

```bash
# BOAZ environment
export BOAZ_HOME="/full/path/to/BOAZ-MCP/BOAZ_beta"
export PATH="$BOAZ_HOME:$PATH"

# Alias for convenience
alias boaz="python3 $BOAZ_HOME/Boaz.py"
```

Reload shell:
```bash
source ~/.bashrc
```

### Create Output Directory

```bash
cd BOAZ-MCP/BOAZ_beta
mkdir -p output
```

### Optional: Enable Bash Completion

```bash
# Add to ~/.bashrc
eval "$(register-python-argcomplete boaz)"
```

## Upgrading

### Update BOAZ

```bash
cd BOAZ-MCP
git pull origin main

# Re-run setup if dependencies changed
./setup.sh
```

### Rebuild LLVM Obfuscators

```bash
# If LLVM updates are available
cd BOAZ_beta
rm -rf akira_built llvm_obfuscator_pluto

# Re-run LLVM installation steps
# Follow Steps 7-8 from Manual Installation
```

## Uninstallation

### Remove BOAZ

```bash
# Remove BOAZ directory
cd ~
rm -rf BOAZ-MCP

# Remove Python packages
pip3 uninstall -y pyinstaller cryptography base58

# Remove MCP configuration
nano ~/Library/Application\ Support/Claude/claude_desktop_config.json
# Remove the "boaz" entry
```

### Remove System Dependencies (Optional)

```bash
# Remove build tools (only if not needed by other software)
sudo apt remove --purge cmake ninja-build mingw-w64 wine

# Remove orphaned packages
sudo apt autoremove -y
```

## Next Steps

After successful installation:

1. Read [USAGE.md](USAGE.md) for usage examples
2. Review [API.md](API.md) for MCP tool reference
3. Test with sample payloads in isolated environment
4. Configure Claude Desktop for AI-assisted workflows

## Support

For installation issues:
- Check [Troubleshooting](#troubleshooting) section
- Review GitHub Issues
- Consult BOAZ community forums

---

**Installation Complete!** Proceed to [USAGE.md](USAGE.md) for operational guidance.
