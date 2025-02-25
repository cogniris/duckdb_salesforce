#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Function to print status messages
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

# Function to print error messages
print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to print warning messages
print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if DuckDB CLI is installed
if ! command -v duckdb &> /dev/null; then
    print_error "DuckDB CLI not found. Please install it first."
    print_warning "You can install it with: brew install duckdb"
    exit 1
fi

# Build the extension using the standard build process
print_status "Building extension in debug mode..."
make debug

# Check if build was successful
if [ $? -ne 0 ]; then
    print_error "Build failed. Please check the error messages above."
    exit 1
fi

# Create a test SQL file
print_status "Creating test SQL file..."
cat > test.sql << EOF
-- Load the extension
LOAD 'build/debug/extension/salesforce/salesforce.duckdb_extension';

-- Test the version function
SELECT salesforce('test') AS version;

-- Test the salesforce_object function with a small limit
SELECT * FROM salesforce_object('Account') LIMIT 5;
EOF

# Create a debug database
print_status "Creating debug database..."
rm -f debug.db

# Run the test with DuckDB CLI
print_status "Running test..."
duckdb debug.db -echo -c "$(cat test.sql)" || {
    print_error "Test failed. Please check the error messages above."
    exit 1
}

print_status "Test completed successfully!"
print_status "Debug database saved to debug.db"
print_status "You can examine it with: duckdb debug.db" 