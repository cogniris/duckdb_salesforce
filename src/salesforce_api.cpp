#include "salesforce_api.hpp"
#include "salesforce_soql.hpp"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.hpp"

using namespace duckdb_httplib_openssl;

namespace duckdb {

std::pair<std::vector<SalesforceRecord>, std::string> ProcessSalesforceResponse(const std::string &response_string) {
	std::vector<SalesforceRecord> records;
	std::string next_records_url = "";

	std::shared_ptr<yyjson_doc> doc(
		yyjson_read(response_string.c_str(), response_string.size(), YYJSON_READ_ALLOW_INVALID_UNICODE),
		yyjson_doc_free);
	if (!doc) {
		throw std::runtime_error("Failed to parse Salesforce response");
	}

	yyjson_val *root = yyjson_doc_get_root(doc.get());
	if (!root || yyjson_get_type(root) != YYJSON_TYPE_OBJ) {
		throw std::runtime_error("Invalid JSON response from Salesforce");
	}

	yyjson_val *records_arr = yyjson_obj_get(root, "records");
	if (!records_arr || yyjson_get_type(records_arr) != YYJSON_TYPE_ARR) {
		throw std::runtime_error("Missing or invalid 'records' array in Salesforce response");
	}

	size_t idx, max;
	yyjson_val *record;
	yyjson_arr_foreach(records_arr, idx, max, record) {
		records.emplace_back(doc, record);
	}

	yyjson_val *next_records_url_val = yyjson_obj_get(root, "nextRecordsUrl");
	if (next_records_url_val && yyjson_is_str(next_records_url_val)) {
		next_records_url = yyjson_get_str(next_records_url_val);
	}

	return {records, next_records_url};
}

std::pair<std::vector<SalesforceRecord>, std::string> ExecuteSalesforceQuery(
	const std::string &query,
	SalesforceCredentials &credentials,
	std::mutex &credentials_mutex) {

	std::string url = "/services/data/" + credentials.api_version + "/query";
	Params params;
	params.emplace("q", query);

	auto response_string = MakeAuthenticatedGet(credentials, credentials_mutex, "execute Salesforce query",
		[&](Client &c) { return c.Get(url.c_str(), params, Headers{}); });

	try {
		return ProcessSalesforceResponse(response_string);
	} catch (const std::exception &e) {
		throw std::runtime_error("Failed to parse Salesforce query response: " + std::string(e.what()));
	}
}

std::pair<std::vector<SalesforceRecord>, std::string> ContinueSalesforceQuery(
	const std::string &next_records_url,
	SalesforceCredentials &credentials,
	std::mutex &credentials_mutex) {

	auto response_string = MakeAuthenticatedGet(credentials, credentials_mutex, "continue Salesforce query",
		[&](Client &c) { return c.Get(next_records_url.c_str()); });

	try {
		return ProcessSalesforceResponse(response_string);
	} catch (const std::exception &e) {
		throw std::runtime_error("Failed to parse Salesforce query response: " + std::string(e.what()));
	}
}

std::vector<SalesforceField> FetchSalesforceObjectMetadata(const std::string &object_name, SalesforceCredentials &credentials) {
	auto &cache = SalesforceMetadataCache::GetInstance();
	std::vector<SalesforceField> cached_fields;
	if (cache.TryGetFromCache(object_name, cached_fields)) {
		return cached_fields;
	}

	std::vector<SalesforceField> fields;

	std::string url = "/services/data/" + credentials.api_version + "/sobjects/" + object_name + "/describe";
	std::mutex local_mutex;
	auto response_string = MakeAuthenticatedGet(credentials, local_mutex, "fetch Salesforce object metadata",
		[&](Client &c) { return c.Get(url.c_str()); });

	try {
		yyjson_read_flag flags = YYJSON_READ_ALLOW_INVALID_UNICODE;
		yyjson_doc *doc = yyjson_read(response_string.c_str(), response_string.size(), flags);
		if (!doc) {
			throw std::runtime_error("Failed to parse Salesforce metadata response");
		}

		yyjson_val *root = yyjson_doc_get_root(doc);
		if (!root || yyjson_get_type(root) != YYJSON_TYPE_OBJ) {
			yyjson_doc_free(doc);
			throw std::runtime_error("Invalid JSON response from Salesforce");
		}

		yyjson_val *fields_arr = yyjson_obj_get(root, "fields");
		if (!fields_arr || yyjson_get_type(fields_arr) != YYJSON_TYPE_ARR) {
			yyjson_doc_free(doc);
			throw std::runtime_error("Missing or invalid 'fields' array in Salesforce metadata response");
		}

		size_t idx, max;
		yyjson_val *field;
		yyjson_arr_foreach(fields_arr, idx, max, field) {
			if (yyjson_get_type(field) != YYJSON_TYPE_OBJ) {
				continue;
			}

			SalesforceField sf_field;

			yyjson_val *name = yyjson_obj_get(field, "name");
			yyjson_val *type = yyjson_obj_get(field, "type");
			yyjson_val *nillable = yyjson_obj_get(field, "nillable");

			if (name && type) {
				sf_field.name = yyjson_get_str(name);
				sf_field.type = yyjson_get_str(type);
				sf_field.nillable = nillable ? yyjson_get_bool(nillable) : false;
				sf_field.duckdb_type = MapSalesforceType(sf_field.type);
				fields.push_back(sf_field);
			}
		}

		yyjson_doc_free(doc);

		cache.AddToCache(object_name, fields);
	} catch (const std::exception &e) {
		throw std::runtime_error("Failed to parse Salesforce metadata: " + std::string(e.what()));
	}

	return fields;
}

} // namespace duckdb
