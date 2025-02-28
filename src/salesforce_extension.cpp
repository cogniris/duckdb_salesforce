#define DUCKDB_EXTENSION_MAIN

#include "salesforce_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/parser/expression/constant_expression.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/tableref/table_function_ref.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/main/extension_util.hpp"
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>
#include "salesforce_object.hpp"
#include "salesforce_secret.hpp"
#include "duckdb/function/replacement_scan.hpp"

// OpenSSL linked through vcpkg
#include <openssl/opensslv.h>
#include <vector>

namespace duckdb {

std::string ExtractBeforeDot(const std::string& input) {
    size_t dotPos = input.find('.');
    if (dotPos != std::string::npos) {
        return input.substr(0, dotPos);
    }
    return input; // Return the entire string if no dot is found
}

std::string ExtractAfterDot(const std::string& input) {
    size_t dotPos = input.find('.');
    if (dotPos != std::string::npos) {
        return input.substr(dotPos + 1);
    }
    return input;
}

unique_ptr<TableRef> ReadObjectReplacement(ClientContext &context, ReplacementScanInput &input,
                                            optional_ptr<ReplacementScanData> data) {
	auto table_name = ReplacementScan::GetFullPath(input);
    std::string org_name = ExtractBeforeDot(table_name);

    auto &secret_manager = SecretManager::Get(context);
    auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
    auto secret_match = secret_manager.LookupSecret(transaction, org_name, "salesforce");
    
    if (!secret_match.HasMatch()) {
        return nullptr;
    }

    std::string object_name = ExtractAfterDot(table_name);

	auto table_function = make_uniq<TableFunctionRef>();
	vector<unique_ptr<ParsedExpression>> children;
	children.push_back(make_uniq<ConstantExpression>(Value(org_name)));
	children.push_back(make_uniq<ConstantExpression>(Value(object_name)));
	table_function->function = make_uniq<FunctionExpression>("salesforce_object", std::move(children));

	if (!FileSystem::HasGlob(table_name)) {
		auto &fs = FileSystem::GetFileSystem(context);
		table_function->alias = fs.ExtractBaseName(table_name);
	}

	return std::move(table_function);
}

static void LoadInternal(DatabaseInstance &instance) {
	// Load Secret functions
	CreateSalesforceSecretFunctions::Register(instance);

    // Register the salesforce_object table function
    auto salesforce_object_func = make_uniq<SalesforceObjectFunction>();
    ExtensionUtil::RegisterFunction(instance, *salesforce_object_func);

      // Register replacement scan for read_gsheet
    auto &config = DBConfig::GetConfig(instance);
    config.replacement_scans.emplace_back(ReadObjectReplacement);
}

void SalesforceExtension::Load(DuckDB &db) {
	LoadInternal(*db.instance);
}

std::string SalesforceExtension::Name() {
	return "salesforce";
}

std::string SalesforceExtension::Version() const {
#ifdef EXT_VERSION_SALESFORCE
	return EXT_VERSION_SALESFORCE;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_EXTENSION_API void salesforce_init(duckdb::DatabaseInstance &db) {
    duckdb::LoadInternal(db);
}

DUCKDB_EXTENSION_API const char *salesforce_version() {
	return duckdb::DuckDB::LibraryVersion();
}
}

#ifndef DUCKDB_EXTENSION_MAIN
#error DUCKDB_EXTENSION_MAIN not defined
#endif
