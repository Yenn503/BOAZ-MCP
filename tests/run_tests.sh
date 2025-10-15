#!/bin/bash

# BOAZ MCP Server Test Runner
# Runs all test suites and generates coverage report

set -e  # Exit on error

echo "=========================================="
echo "BOAZ MCP Server Test Suite"
echo "=========================================="
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

# Change to project root
cd "$PROJECT_ROOT"

# Check if pytest is installed
if ! command -v pytest &> /dev/null; then
    echo -e "${RED}Error: pytest is not installed${NC}"
    echo "Please install test dependencies: pip install -r tests/requirements.txt"
    exit 1
fi

# Check if the server file exists
if [ ! -f "boaz_mcp_server.py" ]; then
    echo -e "${RED}Error: boaz_mcp_server.py not found${NC}"
    exit 1
fi

# Default options
VERBOSE=""
COVERAGE=""
SPECIFIC_TEST=""
MARKERS=""
SHOW_COVERAGE_REPORT=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE="-v"
            shift
            ;;
        -vv|--very-verbose)
            VERBOSE="-vv"
            shift
            ;;
        -c|--coverage)
            COVERAGE="--cov=boaz_mcp_server --cov-report=html --cov-report=term"
            SHOW_COVERAGE_REPORT=true
            shift
            ;;
        -t|--test)
            SPECIFIC_TEST="$2"
            shift 2
            ;;
        -m|--marker)
            MARKERS="-m $2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -v, --verbose           Verbose output"
            echo "  -vv, --very-verbose     Very verbose output"
            echo "  -c, --coverage          Generate coverage report"
            echo "  -t, --test TEST_FILE    Run specific test file"
            echo "  -m, --marker MARKER     Run tests with specific marker"
            echo "  -h, --help              Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                      # Run all tests"
            echo "  $0 -v                   # Run with verbose output"
            echo "  $0 -c                   # Run with coverage report"
            echo "  $0 -t test_security.py  # Run specific test file"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
    esac
done

echo -e "${YELLOW}Running BOAZ MCP Server Tests...${NC}"
echo ""

# Determine which tests to run
if [ -n "$SPECIFIC_TEST" ]; then
    TEST_PATH="tests/$SPECIFIC_TEST"
    if [ ! -f "$TEST_PATH" ]; then
        echo -e "${RED}Error: Test file not found: $TEST_PATH${NC}"
        exit 1
    fi
    echo -e "${YELLOW}Running specific test: $SPECIFIC_TEST${NC}"
    echo ""
else
    TEST_PATH="tests/"
    echo -e "${YELLOW}Running all tests in tests/ directory${NC}"
    echo ""
fi

# Run the tests
echo "----------------------------------------"
echo "Test Execution"
echo "----------------------------------------"

if pytest $VERBOSE $COVERAGE $MARKERS "$TEST_PATH"; then
    echo ""
    echo -e "${GREEN}=========================================="
    echo "All tests passed successfully!"
    echo -e "==========================================${NC}"
    TEST_RESULT=0
else
    echo ""
    echo -e "${RED}=========================================="
    echo "Some tests failed!"
    echo -e "==========================================${NC}"
    TEST_RESULT=1
fi

# Show coverage report location if generated
if [ "$SHOW_COVERAGE_REPORT" = true ] && [ $TEST_RESULT -eq 0 ]; then
    echo ""
    echo -e "${GREEN}Coverage report generated:${NC}"
    echo "  HTML: file://$PROJECT_ROOT/htmlcov/index.html"
    echo ""
    echo "To view the HTML coverage report, open:"
    echo "  open htmlcov/index.html"
fi

echo ""
echo "----------------------------------------"
echo "Test Summary"
echo "----------------------------------------"

# Count test files
TEST_FILES=$(find tests -name "test_*.py" | wc -l | tr -d ' ')
echo "Test files: $TEST_FILES"

# List test files
echo ""
echo "Available test suites:"
echo "  - test_mcp_protocol.py     (MCP protocol compliance)"
echo "  - test_security.py         (Security measures)"
echo "  - test_boaz_integration.py (BOAZ integration)"
echo "  - test_tools.py            (Tool functionality)"

echo ""
exit $TEST_RESULT
