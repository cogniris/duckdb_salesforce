#pragma once

#include "duckdb.hpp"
#include "duckdb/function/table_function.hpp"
#include "salesforce_metadata_cache.hpp"
#include <string>
#include <vector>
#include <sstream>

#include "yyjson.hpp"

using namespace duckdb_yyjson;

namespace duckdb {

// Forward declarations
struct SalesforceScanState;
struct SalesforceScanBindData;

// Salesforce data type mapping to DuckDB types
LogicalType MapSalesforceType(const std::string &sf_type);

// Convert Salesforce JSON value to DuckDB value
Value ConvertSalesforceValue(yyjson_val *value, const LogicalType &type);

// Generate full SOQL query from scan state and bind data
std::string GenerateSOQLQuery(const SalesforceScanState &state, const SalesforceScanBindData &bind_data);

// Generate WHERE clause from DuckDB filter pushdown
std::string GenerateSOQLWhereClause(const SalesforceScanState &state, const TableFilterSet &filterSet);

} // namespace duckdb
