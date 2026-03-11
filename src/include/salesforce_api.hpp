#pragma once

#include "duckdb.hpp"
#include "salesforce_auth.hpp"
#include "salesforce_metadata_cache.hpp"
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <utility>

#include "yyjson.hpp"

using namespace duckdb_yyjson;

namespace duckdb {

// Define a structure to hold Salesforce record data
struct SalesforceRecord {
	// Shared ownership of the parsed JSON document; root points into it
	std::shared_ptr<yyjson_doc> doc;
	yyjson_val *root;

	SalesforceRecord(std::shared_ptr<yyjson_doc> d, yyjson_val *r) : doc(std::move(d)), root(r) {}
	SalesforceRecord() : doc(nullptr), root(nullptr) {}

	// Default copy/move are correct: shared_ptr is reference-counted,
	// root is a non-owning pointer into the shared document.
	SalesforceRecord(const SalesforceRecord &) = default;
	SalesforceRecord(SalesforceRecord &&) = default;
	SalesforceRecord& operator=(const SalesforceRecord &) = default;
	SalesforceRecord& operator=(SalesforceRecord &&) = default;
	~SalesforceRecord() = default;

	// Check if a value is null
	bool is_null() const {
		return root == nullptr || yyjson_is_null(root);
	}

	// Get a field from the record
	yyjson_val* operator[](const char* key) const {
		return yyjson_obj_get(root, key);
	}
};

// Process Salesforce API response JSON into records + next page URL
std::pair<std::vector<SalesforceRecord>, std::string> ProcessSalesforceResponse(const std::string &response_string);

// Execute a SOQL query against Salesforce
std::pair<std::vector<SalesforceRecord>, std::string> ExecuteSalesforceQuery(
	const std::string &query,
	SalesforceCredentials &credentials,
	std::mutex &credentials_mutex);

// Continue a paginated SOQL query
std::pair<std::vector<SalesforceRecord>, std::string> ContinueSalesforceQuery(
	const std::string &next_records_url,
	SalesforceCredentials &credentials,
	std::mutex &credentials_mutex);

// Fetch Salesforce object metadata (with caching)
std::vector<SalesforceField> FetchSalesforceObjectMetadata(
	const std::string &object_name,
	SalesforceCredentials &credentials);

} // namespace duckdb
