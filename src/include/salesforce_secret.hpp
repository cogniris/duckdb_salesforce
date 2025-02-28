#pragma once

#include "salesforce_extension.hpp"
#include "duckdb.hpp"
#include <duckdb/main/secret/secret.hpp>


namespace duckdb {
struct CreateSecretInput;
class CreateSecretFunction;

struct CreateSalesforceSecretFunctions {
public:
	//! Register all CreateSecretFunctions
	static void Register(DatabaseInstance &instance);
};

} // namespace duckdb