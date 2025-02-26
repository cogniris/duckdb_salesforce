#include "salesforce_object.hpp"
#include "include/salesforce_metadata_cache.hpp"
#include "duckdb.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/common/types/date.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/planner/filter/optional_filter.hpp"
#include <curl/curl.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <iostream>
#include <sstream>
#include <mutex>
#include "nlohmann/json.hpp"

using json = nlohmann::json;

namespace duckdb {

// Salesforce OAuth credentials for username/password flow
struct SalesforceCredentials {
    // OAuth client credentials
    std::string client_id = "";
    std::string client_secret = "";
    
    // User credentials
    std::string username = "";
    std::string password = "";
    
    // OAuth endpoints
    std::string login_url = "https://test.salesforce.com";
    
    // Token information (will be populated during authentication)
    std::string access_token;
    std::string instance_url;
    std::string refresh_token;
    time_t token_expiry = 0;
};

// Callback function for CURL to write response data
static size_t WriteCallback(void *contents, size_t size, size_t nmemb, std::string *s) {
    size_t newLength = size * nmemb;
    try {
        s->append((char*)contents, newLength);
        return newLength;
    } catch(std::bad_alloc &e) {
        return 0;
    }
}

// Function to authenticate with Salesforce using username/password flow
static bool AuthenticateWithSalesforce(SalesforceCredentials &credentials) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("Failed to initialize CURL for authentication");
    }
    
    // Prepare the OAuth request
    std::string post_fields = "grant_type=password";
    
    // Properly handle curl_easy_escape results
    char* escaped_client_id = curl_easy_escape(curl, credentials.client_id.c_str(), credentials.client_id.length());
    char* escaped_client_secret = curl_easy_escape(curl, credentials.client_secret.c_str(), credentials.client_secret.length());
    char* escaped_username = curl_easy_escape(curl, credentials.username.c_str(), credentials.username.length());
    char* escaped_password = curl_easy_escape(curl, credentials.password.c_str(), credentials.password.length());
    
    post_fields += "&client_id=" + std::string(escaped_client_id);
    post_fields += "&client_secret=" + std::string(escaped_client_secret);
    post_fields += "&username=" + std::string(escaped_username);
    post_fields += "&password=" + std::string(escaped_password);
    
    // Free allocated memory
    curl_free(escaped_client_id);
    curl_free(escaped_client_secret);
    curl_free(escaped_username);
    curl_free(escaped_password);
    
    std::string url = credentials.login_url + "/services/oauth2/token";
    std::string response_string;
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
    
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        throw std::runtime_error("Failed to authenticate with Salesforce: " + std::string(curl_easy_strerror(res)));
    }
    
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);
    
    if (http_code != 200) {
        throw std::runtime_error("Salesforce authentication failed with code: " + std::to_string(http_code) + 
                                "\nRequest (" + url + "): " + post_fields +
                                "\nResponse: " + response_string);
    }
    
    try {
        json response = json::parse(response_string);
        
        credentials.access_token = response["access_token"];
        credentials.instance_url = response["instance_url"];
        
        // Set token expiry (typically 2 hours for Salesforce)
        credentials.token_expiry = time(nullptr) + 7200; // 2 hours
        
        if (response.contains("refresh_token")) {
            credentials.refresh_token = response["refresh_token"];
        }
        
        return true;
    } catch (const std::exception &e) {
        throw std::runtime_error("Failed to parse Salesforce authentication response: " + std::string(e.what()));
    }
}

// Function to ensure we have a valid token
static void EnsureValidToken(SalesforceCredentials &credentials) {
    // If token is expired or not set, authenticate
    if (credentials.access_token.empty() || time(nullptr) >= credentials.token_expiry) {
        AuthenticateWithSalesforce(credentials);
    }
}

// Structure to hold Salesforce scan bind data
struct SalesforceScanBindData : public TableFunctionData {
    long row_limit;
    std::string table_name;
    std::vector<SalesforceField> fields;
    SalesforceCredentials credentials;
};

// Structure to hold Salesforce scan state
struct SalesforceScanState : public LocalTableFunctionState {
    std::vector<SalesforceField> selected_fields;
    std::string where_clause;
    std::vector<json> records;
    size_t current_row = 0;
    bool finished = false;
};

// Function to fetch Salesforce object metadata
static std::vector<SalesforceField> FetchSalesforceObjectMetadata(const std::string &object_name, SalesforceCredentials &credentials) {
    // Check if metadata is in cache
    auto cache = SalesforceMetadataCache::GetInstance();
    if (cache->IsInCache(object_name)) {
        return cache->GetFromCache(object_name);
    }
    
    // If not in cache, fetch from Salesforce API
    std::vector<SalesforceField> fields;
    
    // Ensure we have a valid token
    EnsureValidToken(credentials);
    
    CURL *curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("Failed to initialize CURL");
    }
    
    std::string url = credentials.instance_url + "/services/data/v56.0/sobjects/" + object_name + "/describe";
    std::string response_string;
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
    
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, ("Authorization: Bearer " + credentials.access_token).c_str());
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        throw std::runtime_error("Failed to fetch Salesforce object metadata: " + std::string(curl_easy_strerror(res)));
    }
    
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);
    
    if (http_code == 401) {
        // Token expired, refresh and try again
        AuthenticateWithSalesforce(credentials);
        return FetchSalesforceObjectMetadata(object_name, credentials);
    } else if (http_code != 200) {
        throw std::runtime_error("Salesforce API returned error code: " + std::to_string(http_code) + "\nResponse: " + response_string);
    }
    
    try {
        json response = json::parse(response_string);
        for (const auto &field : response["fields"]) {
            SalesforceField sf_field;
            sf_field.name = field["name"];
            sf_field.type = field["type"];
            sf_field.nillable = field["nillable"];
            sf_field.duckdb_type = MapSalesforceType(sf_field.type);
            fields.push_back(sf_field);
        }
        
        // Add metadata to cache
        cache->AddToCache(object_name, fields);
    } catch (const std::exception &e) {
        throw std::runtime_error("Failed to parse Salesforce metadata: " + std::string(e.what()));
    }
    
    return fields;
}

// Function to execute SOQL query against Salesforce
static std::vector<json> ExecuteSalesforceQuery(const std::string &query, SalesforceCredentials &credentials) {
    std::vector<json> records;
    
    // Ensure we have a valid token
    EnsureValidToken(credentials);
    
    CURL *curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("Failed to initialize CURL");
    }
    
    std::string encoded_query;
    char *encoded = curl_easy_escape(curl, query.c_str(), query.length());
    if (encoded) {
        encoded_query = encoded;
        curl_free(encoded);
    } else {
        curl_easy_cleanup(curl);
        throw std::runtime_error("Failed to URL encode SOQL query");
    }
    
    std::string url = credentials.instance_url + "/services/data/v56.0/query?q=" + encoded_query;
    std::string response_string;
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
    
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, ("Authorization: Bearer " + credentials.access_token).c_str());
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        throw std::runtime_error("Failed to execute Salesforce query: " + std::string(curl_easy_strerror(res)));
    }
    
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);
    
    if (http_code == 401) {
        // Token expired, refresh and try again
        AuthenticateWithSalesforce(credentials);
        return ExecuteSalesforceQuery(query, credentials);
    } else if (http_code != 200) {
        throw std::runtime_error("Salesforce API returned error code: " + std::to_string(http_code) + "\nResponse: " + response_string);
    }
    
    try {
        json response = json::parse(response_string);
        for (const auto &record : response["records"]) {
            records.push_back(record);
        }
        
        // Handle pagination if needed
        std::string next_records_url = response.value("nextRecordsUrl", "");
        while (!next_records_url.empty()) {
            CURL *next_curl = curl_easy_init();
            if (!next_curl) {
                throw std::runtime_error("Failed to initialize CURL for pagination");
            }
            
            std::string next_url = credentials.instance_url + next_records_url;
            std::string next_response_string;
            
            curl_easy_setopt(next_curl, CURLOPT_URL, next_url.c_str());
            curl_easy_setopt(next_curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(next_curl, CURLOPT_WRITEDATA, &next_response_string);
            
            struct curl_slist *next_headers = NULL;
            next_headers = curl_slist_append(next_headers, ("Authorization: Bearer " + credentials.access_token).c_str());
            next_headers = curl_slist_append(next_headers, "Content-Type: application/json");
            curl_easy_setopt(next_curl, CURLOPT_HTTPHEADER, next_headers);
            
            res = curl_easy_perform(next_curl);
            curl_slist_free_all(next_headers);
            
            if (res != CURLE_OK) {
                curl_easy_cleanup(next_curl);
                throw std::runtime_error("Failed to fetch next page: " + std::string(curl_easy_strerror(res)));
            }
            
            long next_http_code = 0;
            curl_easy_getinfo(next_curl, CURLINFO_RESPONSE_CODE, &next_http_code);
            curl_easy_cleanup(next_curl);
            
            if (next_http_code == 401) {
                // Token expired, refresh and try again with the original query
                AuthenticateWithSalesforce(credentials);
                return ExecuteSalesforceQuery(query, credentials);
            } else if (next_http_code != 200) {
                throw std::runtime_error("Salesforce API returned error code for pagination: " + std::to_string(next_http_code));
            }
            
            json next_response = json::parse(next_response_string);
            for (const auto &record : next_response["records"]) {
                records.push_back(record);
            }
            
            next_records_url = next_response.value("nextRecordsUrl", "");
        }
    } catch (const std::exception &e) {
        throw std::runtime_error("Failed to parse Salesforce query response: " + std::string(e.what()));
    }
    
    return records;
}

// Convert Salesforce value to DuckDB value
static Value ConvertSalesforceValue(const json &value, const LogicalType &type, const std::string &field_name) {
    if (value.is_null()) {
        return Value(type);
    }
    
    switch (type.id()) {
        case LogicalTypeId::VARCHAR:
            return Value(value.get<std::string>());
        case LogicalTypeId::BOOLEAN:
            return Value::BOOLEAN(value.get<bool>());
        case LogicalTypeId::INTEGER:
            return Value::INTEGER(value.get<int32_t>());
        case LogicalTypeId::DOUBLE:
            return Value::DOUBLE(value.get<double>());   
        case LogicalTypeId::DATE: {
            std::string date_str = value.get<std::string>();
            date_t date_val;
            bool special;
            idx_t pos = 0;
            DateCastResult result = Date::TryConvertDate(date_str.c_str(), date_str.length(), pos, date_val, special);
            if (result != DateCastResult::SUCCESS) {
                throw std::runtime_error("Failed to convert Salesforce date value: " + date_str);
            }
            return Value::DATE(date_val);
        }
        case LogicalTypeId::TIMESTAMP: {
            std::string ts_str = value.get<std::string>();
            timestamp_t ts_val;
            TimestampCastResult result = Timestamp::TryConvertTimestamp(ts_str.c_str(), ts_str.length(), ts_val);
            if (result != TimestampCastResult::SUCCESS) {
                throw std::runtime_error("Failed to convert Salesforce timestamp value: " + ts_str);
            }
            return Value::TIMESTAMP(ts_val);
        }       
        default:
            return Value(value.get<std::string>());
    }
}

static void SalesforceObjectScan(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
    auto &bind_data = (SalesforceScanBindData &)*data.bind_data;
    auto &state = (SalesforceScanState &)*data.local_state;
    
    if (state.finished) {
        return;
    }
    
    // Set the output size to 0 initially
    output.SetCardinality(0);
    
    if (state.records.empty()) {
        // Build SOQL query
        std::stringstream soql;
        soql << "SELECT ";
        
        // Add selected fields or all fields if none specified
        if (state.selected_fields.empty()) {
            bool first = true;
            for (const auto &field : bind_data.fields) {
                if (!first) soql << ", ";
                soql << field.name;
                first = false;
            }
        } else {
            bool first = true;
            for (const auto &field : state.selected_fields) {
                if (!first) soql << ", ";
                soql << field.name;
                first = false;
            }
        }
        
        soql << " FROM " << bind_data.table_name;
        
        // Add WHERE clause if provided
        if (!state.where_clause.empty()) {
            soql << " WHERE " << state.where_clause;
        }

        if (bind_data.row_limit > 0) {
            soql << " LIMIT " << bind_data.row_limit;
        }
        
        // Execute the query
        try {
            state.records = ExecuteSalesforceQuery(soql.str(), bind_data.credentials);
        } catch (const std::exception &e) {
            throw std::runtime_error("Failed to execute Salesforce query: " + std::string(e.what()));
        }
    }
    
    // If no records, we're done
    if (state.records.empty()) {
        state.finished = true;
        return;
    }
    
    // Determine how many records to process in this chunk
    idx_t count = std::min((idx_t)(state.records.size() - state.current_row), (idx_t)STANDARD_VECTOR_SIZE);
    
    // Set the output cardinality
    output.SetCardinality(count);
    
    // Process each column
    for (idx_t col_idx = 0; col_idx < output.ColumnCount(); col_idx++) {
        auto &column = output.data[col_idx];
        auto &field = state.selected_fields.empty() ? bind_data.fields[col_idx] : state.selected_fields[col_idx];
        
        // Process each row in the chunk
        for (idx_t row_idx = 0; row_idx < count; row_idx++) {
            const auto &record = state.records[state.current_row + row_idx];
            
            try {
                // Handle nested fields (e.g., Owner.Name)
                std::string field_name = field.name;
                json field_value = record;
                
                size_t dot_pos = field_name.find('.');
                while (dot_pos != std::string::npos) {
                    std::string parent = field_name.substr(0, dot_pos);
                    field_name = field_name.substr(dot_pos + 1);
                    
                    if (field_value.contains(parent) && !field_value[parent].is_null()) {
                        field_value = field_value[parent];
                    } else {
                        // Parent field is null or doesn't exist
                        field_value = nullptr;
                        break;
                    }
                    
                    dot_pos = field_name.find('.');
                }
                
                if (!field_value.is_null() && field_value.contains(field_name)) {
                    column.SetValue(row_idx, ConvertSalesforceValue(field_value[field_name], field.duckdb_type, field.name));
                } else {
                    column.SetValue(row_idx, Value(field.duckdb_type));
                }
            } catch (const std::exception &e) {
                // If conversion fails, set to NULL
                column.SetValue(row_idx, Value(field.duckdb_type));
            }
        }
    }
    
    // Update the current row
    state.current_row += count;
    
    // Check if we've processed all records
    if (state.current_row >= state.records.size()) {
        state.finished = true;
    }
}

static unique_ptr<FunctionData> SalesforceObjectBind(ClientContext &context, TableFunctionBindInput &input,
    vector<LogicalType> &return_types, vector<string> &names) {
    
    auto bind_data = make_uniq<SalesforceScanBindData>();
    
    // Get the object name from the input
    bind_data->table_name = input.inputs[0].GetValue<string>();
    bind_data->row_limit = input.inputs[1].GetValue<u_int32_t>();

    // Set up credentials
    bind_data->credentials = SalesforceCredentials();
    
    try {
        // Fetch metadata for the object
        bind_data->fields = FetchSalesforceObjectMetadata(bind_data->table_name, bind_data->credentials);
        
        // Set up return types and names
        for (const auto &field : bind_data->fields) {
            return_types.push_back(field.duckdb_type);
            names.push_back(field.name);
        }
    } catch (const std::exception &e) {
        throw BinderException("Failed to bind Salesforce object: " + std::string(e.what()));
    }
    
    // Handle projection pushdown
    /*

    */
    
    return std::move(bind_data);
}

static unique_ptr<GlobalTableFunctionState> SalesforceObjectInitGlobalState(ClientContext &context,
    TableFunctionInitInput &input) {
    return nullptr;
}

static void GenerateSOQLWhereClauseInternal(const std::string &column_name, TableFilter *filter, std::stringstream &where_clause) {
    switch (filter->filter_type) {
        case duckdb::TableFilterType::CONSTANT_COMPARISON: 
        case duckdb::TableFilterType::IN_FILTER: {
            where_clause << filter->ToString(column_name).c_str();
            return;
        }
        case duckdb::TableFilterType::IS_NULL: {
            where_clause << column_name << " = NULL";
            return;
        }
        case duckdb::TableFilterType::IS_NOT_NULL: {
            where_clause << column_name << " != NULL";
            return;
        }
        case duckdb::TableFilterType::CONJUNCTION_OR:
        case duckdb::TableFilterType::CONJUNCTION_AND: {
            auto conjuction_filter = reinterpret_cast<duckdb::ConjunctionFilter *>(filter);
            if (conjuction_filter->child_filters.size() > 1) {
                for (idx_t i = 0; i < conjuction_filter->child_filters.size() - 1; i++) {
                    GenerateSOQLWhereClauseInternal(column_name, conjuction_filter->child_filters[i].get(), where_clause);
                    where_clause << (filter->filter_type == duckdb::TableFilterType::CONJUNCTION_OR ? " OR " : " AND ");
                }
            }
            GenerateSOQLWhereClauseInternal(column_name, conjuction_filter->child_filters.back().get(), where_clause);
            return;
        }
        case duckdb::TableFilterType::OPTIONAL_FILTER: {
		    auto optional_filter = reinterpret_cast<duckdb::OptionalFilter *>(filter);
		    return GenerateSOQLWhereClauseInternal(column_name, optional_filter->child_filter.get(), where_clause);
	    }
        default: {
            return;
        }
	}
}

static string GenerateSOQLWhereClause(const SalesforceScanState &state, const TableFilterSet &filterSet) {
    std::stringstream where_clause;
    bool first = true;

    for (const auto& entry : filterSet.filters) {
        if (!first) {
            where_clause << " AND ";
        }

        auto column_name = state.selected_fields[entry.first].name;

        GenerateSOQLWhereClauseInternal(column_name, entry.second.get(), where_clause);

        first = false;
    }

    return where_clause.str();
}

static unique_ptr<LocalTableFunctionState> SalesforceObjectInitLocalState(ExecutionContext &context,
    TableFunctionInitInput &input,
    GlobalTableFunctionState *global_state) {
    
    auto scan_state = make_uniq<SalesforceScanState>();
    auto &bind_data = (SalesforceScanBindData &)*input.bind_data;

    if (input.column_ids.size() > 0) {
        scan_state->selected_fields.clear();
        for (const auto &col_idx : input.column_ids) {
            scan_state->selected_fields.push_back(bind_data.fields[col_idx]);
        }
    }
    
    // Handle filter pushdown
    if (input.filters) {
        scan_state->where_clause = GenerateSOQLWhereClause(*scan_state, *input.filters);
    }

    return std::move(scan_state);
}

SalesforceObjectFunction::SalesforceObjectFunction() 
    : TableFunction(
        "salesforce_object", {LogicalType::VARCHAR, LogicalType::INTEGER}, 
        SalesforceObjectScan, SalesforceObjectBind, 
        SalesforceObjectInitGlobalState, SalesforceObjectInitLocalState) {
    this->projection_pushdown = true;
    this->filter_pushdown = true;
}

} // namespace duckdb 