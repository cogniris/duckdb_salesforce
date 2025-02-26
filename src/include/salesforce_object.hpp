#pragma once

#include "duckdb.hpp"
#include "duckdb/function/table_function.hpp"
#include "salesforce_metadata_cache.hpp"

namespace duckdb {

class SalesforceObjectFunction : public TableFunction {
public:
    SalesforceObjectFunction();
};

} // namespace duckdb 