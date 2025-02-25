#include "duckdb.hpp"
#include "duckdb/function/table_function.hpp"

namespace duckdb {

    class SalesforceScanBindData : public FunctionData {

    };


    class SalesforceScanFunction : public TableFunction {
        public:
          SalesforceScanFunction();
        };
}