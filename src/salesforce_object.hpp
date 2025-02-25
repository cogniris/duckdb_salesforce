#pragma once

#include "duckdb.hpp"
#include "duckdb/function/table_function.hpp"

namespace duckdb {

class SalesforceObjectFunction : public TableFunction {
public:
    SalesforceObjectFunction();
};

} // namespace duckdb 