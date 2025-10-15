#!/bin/bash

# BOAZ MCP Server Test Suite Verification Script
# Verifies that all test files and infrastructure are properly installed

set -e

echo "=========================================="
echo "BOAZ MCP Test Suite Verification"
echo "=========================================="
echo ""

PROJECT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$PROJECT_ROOT"

ERRORS=0

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_file() {
    if [ -f "$1" ]; then
        echo -e "${GREEN}✓${NC} $1"
    else
        echo -e "${RED}✗${NC} $1 (MISSING)"
        ERRORS=$((ERRORS + 1))
    fi
}

check_executable() {
    if [ -x "$1" ]; then
        echo -e "${GREEN}✓${NC} $1 (executable)"
    else
        echo -e "${YELLOW}!${NC} $1 (not executable)"
        echo "  Run: chmod +x $1"
    fi
}

echo "Checking Core Files..."
echo "----------------------------------------"
check_file "boaz_mcp_server.py"
check_file "pytest.ini"
check_file "TESTING.md"
check_file "TEST_SUITE_SUMMARY.md"

echo ""
echo "Checking Test Files..."
echo "----------------------------------------"
check_file "tests/__init__.py"
check_file "tests/conftest.py"
check_file "tests/README.md"
check_file "tests/requirements.txt"
check_file "tests/run_tests.sh"
check_file "tests/test_mcp_protocol.py"
check_file "tests/test_security.py"
check_file "tests/test_boaz_integration.py"
check_file "tests/test_tools.py"

echo ""
echo "Checking CI/CD Files..."
echo "----------------------------------------"
check_file ".github/workflows/test.yml"

echo ""
echo "Checking Executables..."
echo "----------------------------------------"
check_executable "tests/run_tests.sh"
check_executable "verify_test_suite.sh"

echo ""
echo "Counting Tests..."
echo "----------------------------------------"
if command -v grep &> /dev/null; then
    PROTOCOL_TESTS=$(grep -c "def test_" tests/test_mcp_protocol.py 2>/dev/null || echo "0")
    SECURITY_TESTS=$(grep -c "def test_" tests/test_security.py 2>/dev/null || echo "0")
    INTEGRATION_TESTS=$(grep -c "def test_" tests/test_boaz_integration.py 2>/dev/null || echo "0")
    TOOL_TESTS=$(grep -c "def test_" tests/test_tools.py 2>/dev/null || echo "0")
    TOTAL_TESTS=$((PROTOCOL_TESTS + SECURITY_TESTS + INTEGRATION_TESTS + TOOL_TESTS))

    echo "Protocol tests:     $PROTOCOL_TESTS"
    echo "Security tests:     $SECURITY_TESTS"
    echo "Integration tests:  $INTEGRATION_TESTS"
    echo "Tool tests:         $TOOL_TESTS"
    echo "----------------------------------------"
    echo -e "${GREEN}Total tests:        $TOTAL_TESTS${NC}"
fi

echo ""
echo "Checking Python Dependencies..."
echo "----------------------------------------"
if command -v python3 &> /dev/null; then
    echo -e "${GREEN}✓${NC} Python 3 installed"
    PYTHON_VERSION=$(python3 --version)
    echo "  $PYTHON_VERSION"
else
    echo -e "${RED}✗${NC} Python 3 not found"
    ERRORS=$((ERRORS + 1))
fi

if command -v pytest &> /dev/null; then
    echo -e "${GREEN}✓${NC} pytest installed"
    PYTEST_VERSION=$(pytest --version | head -1)
    echo "  $PYTEST_VERSION"
else
    echo -e "${YELLOW}!${NC} pytest not installed"
    echo "  Run: pip install -r tests/requirements.txt"
fi

echo ""
echo "File Statistics..."
echo "----------------------------------------"
if [ -d "tests" ]; then
    TEST_FILES=$(find tests -name "test_*.py" | wc -l | tr -d ' ')
    TOTAL_FILES=$(find tests -type f | wc -l | tr -d ' ')
    TEST_LINES=$(cat tests/test_*.py 2>/dev/null | wc -l | tr -d ' ')

    echo "Test files:         $TEST_FILES"
    echo "Total test files:   $TOTAL_FILES"
    echo "Lines of test code: $TEST_LINES"
fi

echo ""
echo "=========================================="
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}✓ Test Suite Verification PASSED${NC}"
    echo "All required files are in place!"
    echo ""
    echo "Next steps:"
    echo "1. Install dependencies: pip install -r tests/requirements.txt"
    echo "2. Run tests: ./tests/run_tests.sh"
    echo "3. View documentation: cat TESTING.md"
else
    echo -e "${RED}✗ Test Suite Verification FAILED${NC}"
    echo "$ERRORS file(s) missing or have issues"
    echo "Please check the errors above."
    exit 1
fi
echo "=========================================="
