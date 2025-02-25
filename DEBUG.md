# Debugging the Salesforce Extension

This document provides instructions on how to debug the Salesforce DuckDB extension.

## Prerequisites

- DuckDB CLI installed (`brew install duckdb`)
- VSCode with C/C++ extension
- LLDB debugger

## Debugging Methods

### 1. Using the Test Script

The simplest way to test the extension is to use the provided test script:

```bash
./test_extension.sh
```

This script:
1. Builds the extension in debug mode
2. Creates a test SQL file
3. Runs the test with DuckDB CLI
4. Saves the results to a debug database

### 2. Using VSCode Debugger

Two debug configurations are provided in VSCode:

#### Debug Extension with DuckDB

This configuration launches DuckDB with the extension loaded and runs a simple test query.

1. Set breakpoints in your extension code
2. Press F5 or select "Debug Extension with DuckDB" from the debug dropdown
3. The debugger will stop at your breakpoints

#### Debug Extension Script

This configuration runs a more comprehensive test script:

1. Set breakpoints in your extension code
2. Press F5 or select "Debug Extension Script" from the debug dropdown
3. The debugger will stop at your breakpoints

## Debugging Tips

1. **Add Logging**: Add logging statements to your code to help track execution flow:
   ```cpp
   std::cerr << "Debug: " << some_variable << std::endl;
   ```

2. **Inspect Memory**: Use the debugger to inspect variables and memory

3. **Step Through Code**: Use the debugger to step through code line by line

4. **Check Return Values**: Always check return values from API calls

## Common Issues

1. **Extension Not Found**: Make sure the path to the extension is correct
2. **Segmentation Fault**: Usually indicates a memory access issue
3. **Symbol Not Found**: Make sure all dependencies are properly linked

## Useful Commands

- Build in debug mode: `make debug`
- Run tests: `./test_extension.sh`
- Examine debug database: `duckdb debug.db` 