#pragma once

#include "duckdb.hpp"
#include "duckdb/function/table_function.hpp"
#include "salesforce_metadata_cache.hpp"
#include "salesforce_auth.hpp"
#include "salesforce_api.hpp"
#include <vector>
#include <string>
#include <mutex>

namespace duckdb {

// Structure to hold Salesforce scan bind data
struct SalesforceScanBindData : public TableFunctionData {
	long row_limit = 0;
	std::string org_secret_name;
	std::string table_name;
	std::vector<SalesforceField> fields;
	SalesforceCredentials credentials;
	std::mutex credentials_mutex;
};

// Structure to hold Salesforce scan state
struct SalesforceScanState : public LocalTableFunctionState {
	std::vector<SalesforceField> selected_fields;
	bool count_only = false;
	std::string where_clause;
	std::vector<SalesforceRecord> records;
	std::string next_records_url;
	size_t current_record_idx = 0;
	size_t current_chunk_idx = 0;
	size_t current_row = 0;
	bool finished = false;
};

class SalesforceObjectFunction : public TableFunction {
public:
	SalesforceObjectFunction();
};

} // namespace duckdb
