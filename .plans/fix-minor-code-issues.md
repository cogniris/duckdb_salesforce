# Fix Minor Code Issues

## Overview
Collection of small code quality fixes across the codebase.

## Changes

### 1. Fix typo: `conjuction_filter` → `conjunction_filter`
- **File:** `src/salesforce_object.cpp` lines 847-855
- Rename all occurrences of the misspelled variable

### 2. Remove unused `Headers headers` variable
- **File:** `src/salesforce_object.cpp` line 494 (lambda in ExecuteSalesforceQuery)
- Changed `Headers h; return c.Get(url, params, h)` → `return c.Get(url, params, Headers{})`

### 3. Fix copy-paste comment
- **File:** `src/salesforce_extension.cpp` line 77
- Change `"read_gsheet"` to `"salesforce_object"` (or similar)

### 4. Fix inconsistent includes
- **File:** `src/salesforce_metadata_cache.cpp` line 1: uses `"include/salesforce_metadata_cache.hpp"`
- **File:** `src/salesforce_object.cpp` line 2: uses `"include/salesforce_metadata_cache.hpp"`
- Other `.cpp` files include headers without the `include/` prefix (e.g., `"salesforce_object.hpp"`)
- The `src/include/` headers themselves use bare names (e.g., `"salesforce_metadata_cache.hpp"`)
- Standardize: since `src/include/` is on the include path, remove the `include/` prefix from `.cpp` includes

### 5. Simplify copy constructor/assignment (SalesforceRecord)
- **File:** `src/salesforce_object.cpp` lines 80-146
- Cannot delete: `std::pair<vector<SalesforceRecord>, string>` requires copy constructibility
- Simplified the copy constructor/assignment (removed redundant flag variable, consolidated null checks)
- Added comments explaining why the round-trip is necessary and that move is preferred

### 6. Fix singleton leak in SalesforceMetadataCache
- **File:** `src/salesforce_metadata_cache.cpp` and `src/include/salesforce_metadata_cache.hpp`
- Replace raw `new` singleton with Meyers' singleton (static local variable)
- Remove the `instance` pointer and `instance_mutex` static members
- Return reference instead of pointer

## Status: COMPLETE
- All 6 items addressed
- Build verified: no new errors or warnings in modified files
- Note: pre-existing build error in `salesforce_secret.cpp` (DuckDB API change) is unrelated
