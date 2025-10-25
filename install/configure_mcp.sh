#!/bin/bash
# Universal MCP Configuration Generator for BOAZ
# Works with Claude Desktop, Continue.dev, Cursor, VS Code, and other MCP clients
# Author: BOAZ Development Team

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Get script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BOAZ_PATH="$PROJECT_ROOT/BOAZ_beta"
MCP_SERVER="$PROJECT_ROOT/boaz_mcp/server.py"

# Print banner
echo -e "${CYAN}"
cat << "EOF"
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║        BOAZ MCP Universal Configuration Generator       ║
║        Works with ALL MCP-compatible AI clients         ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo -e "${BLUE}[INFO]${NC} Detected BOAZ installation at: $PROJECT_ROOT"
echo

# Function to create config JSON
create_config_json() {
    local use_docker=$1

    if [ "$use_docker" = "true" ]; then
        cat << EOF
{
  "mcpServers": {
    "boaz": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "-v", "${HOME}:/host_home:ro",
        "-v", "${PROJECT_ROOT}/BOAZ_beta:/boaz/BOAZ_beta:ro",
        "-v", "${PROJECT_ROOT}/payloads:/boaz/payloads:ro",
        "-v", "${PROJECT_ROOT}/output:/boaz/output",
        "-v", "${PROJECT_ROOT}/boaz_mcp:/boaz/boaz_mcp:ro",
        "mmttxx20/boaz-builder",
        "python3", "/boaz/boaz_mcp/server.py"
      ],
      "env": {
        "BOAZ_PATH": "/boaz/BOAZ_beta",
        "BOAZ_OUTPUT_DIR": "/boaz/output"
      },
      "description": "BOAZ MCP Server (Docker) - AI-assisted red team evasion framework"
    }
  }
}
EOF
    else
        # Check if venv exists, use it if available
        local python_cmd="python3"
        if [ -f "${PROJECT_ROOT}/venv/bin/python" ]; then
            python_cmd="${PROJECT_ROOT}/venv/bin/python"
        fi

        cat << EOF
{
  "mcpServers": {
    "boaz": {
      "command": "${python_cmd}",
      "args": [
        "${MCP_SERVER}"
      ],
      "env": {
        "BOAZ_PATH": "${BOAZ_PATH}",
        "BOAZ_OUTPUT_DIR": "${BOAZ_PATH}/output"
      },
      "description": "BOAZ MCP Server - AI-assisted red team evasion framework"
    }
  }
}
EOF
    fi
}

# Check for Docker
check_docker() {
    if command -v docker &> /dev/null; then
        if docker ps &> /dev/null; then
            return 0
        fi
    fi
    return 1
}

# Configure for Claude Desktop
configure_claude() {
    echo -e "${BLUE}[INFO]${NC} Configuring Claude Desktop..."

    local config_path
    if [[ "$OSTYPE" == "darwin"* ]]; then
        config_path="$HOME/Library/Application Support/Claude/claude_desktop_config.json"
    else
        config_path="$HOME/.config/Claude/claude_desktop_config.json"
    fi

    mkdir -p "$(dirname "$config_path")"

    if [ -f "$config_path" ]; then
        echo -e "${YELLOW}[WARNING]${NC} Config file already exists at: $config_path"
        read -p "Overwrite? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}[SKIP]${NC} Skipping Claude Desktop configuration"
            return
        fi
    fi

    create_config_json "$1" > "$config_path"
    echo -e "${GREEN}[SUCCESS]${NC} Claude Desktop configured at: $config_path"
    echo -e "${YELLOW}[ACTION]${NC} Please restart Claude Desktop to load the new configuration"
}

# Configure for Continue.dev
configure_continue() {
    echo -e "${BLUE}[INFO]${NC} Configuring Continue.dev..."

    local config_path="$HOME/.continue/config.json"

    if [ ! -f "$config_path" ]; then
        echo -e "${YELLOW}[WARNING]${NC} Continue.dev config not found. Creating new config..."
        mkdir -p "$HOME/.continue"
        echo '{"mcpServers":{}}' > "$config_path"
    fi

    # Read existing config
    local existing_config=$(cat "$config_path")
    local boaz_config=$(create_config_json "$1")

    # Merge configs (simple approach - overwrites mcpServers)
    local merged=$(echo "$existing_config" | python3 -c "
import sys, json
existing = json.load(sys.stdin)
boaz = json.loads('''$boaz_config''')
existing['mcpServers'] = existing.get('mcpServers', {})
existing['mcpServers']['boaz'] = boaz['mcpServers']['boaz']
print(json.dumps(existing, indent=2))
")

    echo "$merged" > "$config_path"
    echo -e "${GREEN}[SUCCESS]${NC} Continue.dev configured at: $config_path"
    echo -e "${YELLOW}[ACTION]${NC} Please restart VS Code or reload Continue.dev extension"
}

# Configure for Cursor
configure_cursor() {
    echo -e "${BLUE}[INFO]${NC} Configuring Cursor..."

    local config_path="$HOME/.cursor/mcp_settings.json"

    mkdir -p "$HOME/.cursor"

    if [ -f "$config_path" ]; then
        echo -e "${YELLOW}[WARNING]${NC} Cursor config already exists"
        read -p "Overwrite? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}[SKIP]${NC} Skipping Cursor configuration"
            return
        fi
    fi

    create_config_json "$1" > "$config_path"
    echo -e "${GREEN}[SUCCESS]${NC} Cursor configured at: $config_path"
    echo -e "${YELLOW}[ACTION]${NC} Please restart Cursor IDE"
}

# Configure for VS Code (generic MCP)
configure_vscode() {
    echo -e "${BLUE}[INFO]${NC} Configuring VS Code MCP..."

    local config_path="$HOME/.vscode/mcp.json"

    mkdir -p "$HOME/.vscode"

    create_config_json "$1" > "$config_path"
    echo -e "${GREEN}[SUCCESS]${NC} VS Code MCP configured at: $config_path"
    echo -e "${YELLOW}[NOTE]${NC} Ensure you have an MCP-compatible extension installed"
}

# Configure for Claude Code CLI
configure_claude_code() {
    echo -e "${BLUE}[INFO]${NC} Configuring Claude Code CLI..."

    local config_path="$PROJECT_ROOT/.mcp.json"

    create_config_json "$1" > "$config_path"
    echo -e "${GREEN}[SUCCESS]${NC} Claude Code CLI configured at: $config_path"
    echo -e "${YELLOW}[NOTE]${NC} Restart Claude Code CLI to load the MCP server"
}

# Show manual configuration
show_manual_config() {
    echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Manual Configuration${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
    echo
    echo -e "If your AI client isn't listed above, add this to your MCP config file:"
    echo
    echo -e "${GREEN}$(create_config_json "$1")${NC}"
    echo
    echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
}

# Main menu
main() {
    # Check if Docker is available
    local has_docker=false
    local use_docker=false

    if check_docker; then
        has_docker=true
        echo -e "${GREEN}[DETECTED]${NC} Docker is available"
        echo
        echo "BOAZ can run in two modes:"
        echo "  1. ${GREEN}Docker mode${NC} (RECOMMENDED) - Pre-compiled LLVM, no compilation needed"
        echo "  2. ${YELLOW}Local mode${NC} - Requires LLVM compilation (30-60 mins)"
        echo
        read -p "Use Docker mode? [Y/n] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            use_docker=true
            echo -e "${BLUE}[INFO]${NC} Using Docker mode"

            # Pull Docker image if needed
            if ! docker images | grep -q "mmttxx20/boaz-builder"; then
                echo -e "${BLUE}[INFO]${NC} Pulling BOAZ Docker image (this may take a few minutes)..."
                docker pull mmttxx20/boaz-builder:latest
            fi

            # Create necessary directories
            mkdir -p "$PROJECT_ROOT/payloads"
            mkdir -p "$PROJECT_ROOT/output"
        fi
    else
        echo -e "${YELLOW}[WARNING]${NC} Docker not available. Using local mode."
        echo -e "${YELLOW}[NOTE]${NC} You'll need to compile LLVM obfuscators (run ./setup.sh)"
    fi

    echo
    echo "Select your AI client to configure:"
    echo "  1. Claude Desktop"
    echo "  2. Continue.dev (VS Code)"
    echo "  3. Cursor IDE"
    echo "  4. VS Code (generic MCP)"
    echo "  5. Claude Code CLI"
    echo "  6. All of the above"
    echo "  7. Show manual configuration"
    echo
    read -p "Choice [1-7]: " -n 1 -r
    echo

    case $REPLY in
        1)
            configure_claude "$use_docker"
            ;;
        2)
            configure_continue "$use_docker"
            ;;
        3)
            configure_cursor "$use_docker"
            ;;
        4)
            configure_vscode "$use_docker"
            ;;
        5)
            configure_claude_code "$use_docker"
            ;;
        6)
            configure_claude "$use_docker"
            configure_continue "$use_docker"
            configure_cursor "$use_docker"
            configure_vscode "$use_docker"
            configure_claude_code "$use_docker"
            ;;
        7)
            show_manual_config "$use_docker"
            ;;
        *)
            echo -e "${RED}[ERROR]${NC} Invalid choice"
            exit 1
            ;;
    esac

    echo
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                          ║${NC}"
    echo -e "${GREEN}║        Configuration Complete!                           ║${NC}"
    echo -e "${GREEN}║                                                          ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${BLUE}[INFO]${NC} Next steps:"
    echo "  1. Restart your AI client"
    echo "  2. Look for 'boaz' in available MCP tools"
    echo "  3. Test with: 'List available BOAZ loaders'"
    echo

    if [ "$use_docker" = "true" ]; then
        echo -e "${BLUE}[DOCKER]${NC} Place your payloads in: $PROJECT_ROOT/payloads/"
        echo -e "${BLUE}[DOCKER]${NC} Generated files will be in: $PROJECT_ROOT/output/"
    else
        echo -e "${YELLOW}[LOCAL]${NC} Make sure LLVM obfuscators are compiled (run ./setup.sh)"
    fi
    echo
}

# Run main
main "$@"
