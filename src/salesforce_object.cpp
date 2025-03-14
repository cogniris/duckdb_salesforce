#include "salesforce_object.hpp"
#include "include/salesforce_metadata_cache.hpp"
#include "duckdb.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/common/types/date.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/planner/filter/optional_filter.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <iostream>
#include <sstream>
#include <mutex>

#include "yyjson.hpp"

using namespace duckdb_yyjson;

// Define OpenSSL support before including httplib
#define CPPHTTPLIB_OPENSSL_SUPPORT
// Include httplib from DuckDB's third_party directory
#include "httplib.hpp"

// Use the OpenSSL-enabled version of httplib
using namespace duckdb_httplib_openssl;

namespace duckdb {

    // Salesforce OAuth credentials for username/password flow
struct SalesforceCredentials {
    // OAuth client credentials
    std::string client_id; 
    std::string client_secret; 
    
    // User credentials
    std::string username;
    std::string password;
    
    // OAuth endpoints
    std::string login_url = "https://login.salesforce.com";
    
    // Token information (will be populated during authentication)
    std::string access_token;
    std::string instance_url;
    std::string refresh_token;
    time_t token_expiry = 0;
};

// Structure to hold Salesforce scan bind data
struct SalesforceScanBindData : public TableFunctionData {
    long row_limit;
    std::string org_secret_name;
    std::string table_name;
    std::vector<SalesforceField> fields;
    SalesforceCredentials credentials;
};

// Define a structure to hold Salesforce record data
struct SalesforceRecord {
    // Store the parsed JSON document and root value
    yyjson_doc *doc;
    yyjson_val *root;
    
    // Constructor
    SalesforceRecord(yyjson_doc *d, yyjson_val *r) : doc(d), root(r) {}
    
    // Destructor to free the document
    ~SalesforceRecord() {
        if (doc) {
            yyjson_doc_free(doc);
        }
    }
    
    // Copy constructor
    SalesforceRecord(const SalesforceRecord &other) {
        if (!other.doc || !other.root) {
            doc = nullptr;
            root = nullptr;
            return;
        }
        
        // Create a deep copy of the document
        yyjson_read_flag flags = YYJSON_READ_ALLOW_INVALID_UNICODE;
        char *json_str = yyjson_val_write(other.root, 0, nullptr);
        if (!json_str) {
            doc = nullptr;
            root = nullptr;
            return;
        }
        
        doc = yyjson_read(json_str, strlen(json_str), flags);
        free(json_str);
        
        if (!doc) {
            root = nullptr;
            return;
        }
        
        root = yyjson_doc_get_root(doc);
    }
    
    // Move constructor
    SalesforceRecord(SalesforceRecord &&other) noexcept : doc(other.doc), root(other.root) {
        other.doc = nullptr;
        other.root = nullptr;
    }
    
    // Assignment operator
    SalesforceRecord& operator=(const SalesforceRecord &other) {
        if (this != &other) {
            if (doc) {
                yyjson_doc_free(doc);
            }
            
            if (!other.doc || !other.root) {
                doc = nullptr;
                root = nullptr;
                return *this;
            }
            
            // Create a deep copy of the document
            yyjson_read_flag flags = YYJSON_READ_ALLOW_INVALID_UNICODE;
            char *json_str = yyjson_val_write(other.root, 0, nullptr);
            if (!json_str) {
                doc = nullptr;
                root = nullptr;
                return *this;
            }
            
            doc = yyjson_read(json_str, strlen(json_str), flags);
            free(json_str);
            
            if (!doc) {
                root = nullptr;
                return *this;
            }
            
            root = yyjson_doc_get_root(doc);
        }
        return *this;
    }
    
    // Move assignment operator
    SalesforceRecord& operator=(SalesforceRecord &&other) noexcept {
        if (this != &other) {
            if (doc) {
                yyjson_doc_free(doc);
            }
            
            doc = other.doc;
            root = other.root;
            
            other.doc = nullptr;
            other.root = nullptr;
        }
        return *this;
    }
    
    // Check if a value is null
    bool is_null() const {
        return root == nullptr || yyjson_is_null(root);
    }
    
    // Get a field from the record
    yyjson_val* operator[](const char* key) const {
        return yyjson_obj_get(root, key);
    }
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

// Function to authenticate with Salesforce using username/password flow
static bool AuthenticateWithSalesforce(SalesforceCredentials &credentials) {
    Client client(credentials.login_url.c_str());
    
    // Prepare the OAuth request using httplib's form parameters
    Params form_params;
    form_params.emplace("grant_type", "password");
    form_params.emplace("client_id", credentials.client_id);
    form_params.emplace("client_secret", credentials.client_secret);
    form_params.emplace("username", credentials.username);
    form_params.emplace("password", credentials.password);
    
    std::string url = "/services/oauth2/token";
    
    // Use httplib's Post method with form parameters - this will properly set Content-Type: application/x-www-form-urlencoded
    auto res = client.Post(url.c_str(), form_params);
    
    if (res.error() != Error::Success) {
        throw std::runtime_error("Failed to authenticate with Salesforce: " + std::to_string(static_cast<int>(res.error())));
    }
    
    std::string response_string = res->body;
    long http_code = res->status;
    
    if (http_code != 200) {
        throw std::runtime_error("Salesforce authentication failed with code: " + std::to_string(http_code) + 
                                "\nResponse: " + response_string);
    }
    
    try {
        // Parse JSON using yyjson
        yyjson_read_flag flags = YYJSON_READ_ALLOW_INVALID_UNICODE;
        yyjson_doc *doc = yyjson_read(response_string.c_str(), response_string.size(), flags);
        if (!doc) {
            throw std::runtime_error("Failed to parse Salesforce authentication response");
        }
        
        yyjson_val *root = yyjson_doc_get_root(doc);
        if (!root || yyjson_get_type(root) != YYJSON_TYPE_OBJ) {
            yyjson_doc_free(doc);
            throw std::runtime_error("Invalid JSON response from Salesforce");
        }
        
        // Extract values from JSON
        yyjson_val *access_token = yyjson_obj_get(root, "access_token");
        yyjson_val *instance_url = yyjson_obj_get(root, "instance_url");
        yyjson_val *refresh_token = yyjson_obj_get(root, "refresh_token");
        
        if (!access_token || !instance_url) {
            yyjson_doc_free(doc);
            throw std::runtime_error("Missing required fields in Salesforce authentication response");
        }
        
        credentials.access_token = yyjson_get_str(access_token);
        credentials.instance_url = yyjson_get_str(instance_url);
        
        // Set token expiry (typically 2 hours for Salesforce)
        credentials.token_expiry = time(nullptr) + 7200; // 2 hours
        
        if (refresh_token) {
            credentials.refresh_token = yyjson_get_str(refresh_token);
        }
        
        // Free the document
        yyjson_doc_free(doc);
        
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

static Client GetAuthorisedClient(SalesforceCredentials &credentials) {
    EnsureValidToken(credentials);
    Client client(credentials.instance_url.c_str());
    client.set_bearer_token_auth(credentials.access_token);
    client.set_default_headers({
        {"Content-Type", "application/json"}
    });
    
    return client;
}

// Salesforce data type mapping to DuckDB types
LogicalType MapSalesforceType(const std::string &sf_type) {
    if (sf_type == "id" || sf_type == "string" || sf_type == "reference" || sf_type == "picklist" || 
        sf_type == "multipicklist" || sf_type == "textarea" || sf_type == "phone" || sf_type == "url" || 
        sf_type == "email") {
        return LogicalType::VARCHAR;
    } else if (sf_type == "boolean") {
        return LogicalType::BOOLEAN;
    } else if (sf_type == "int") {
        return LogicalType::INTEGER;
    } else if (sf_type == "double" || sf_type == "currency" || sf_type == "percent") {
        return LogicalType::DOUBLE;
    } else if (sf_type == "date") {
        return LogicalType::DATE;
    } else if (sf_type == "datetime") {
        return LogicalType::TIMESTAMP;
    } else {
        // Default to VARCHAR for unknown types
        return LogicalType::VARCHAR;
    }
}

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
    auto client = GetAuthorisedClient(credentials);
    
    std::string url = "/services/data/v56.0/sobjects/" + object_name + "/describe";
    auto res = client.Get(url.c_str());
    
    if (res.error() != Error::Success) {
        throw std::runtime_error("Failed to fetch Salesforce object metadata: " + std::to_string(static_cast<int>(res.error())));
    }
    
    std::string response_string = res->body;
    long http_code = res->status;
    
    if (http_code == 401) {
        // Token expired, refresh and try again
        AuthenticateWithSalesforce(credentials);
        return FetchSalesforceObjectMetadata(object_name, credentials);
    } else if (http_code != 200) {
        throw std::runtime_error("Salesforce API returned error code: " + std::to_string(http_code) + "\nResponse: " + response_string);
    }
    
    try {
        // Parse JSON using yyjson
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
        
        // Get the fields array
        yyjson_val *fields_arr = yyjson_obj_get(root, "fields");
        if (!fields_arr || yyjson_get_type(fields_arr) != YYJSON_TYPE_ARR) {
            yyjson_doc_free(doc);
            throw std::runtime_error("Missing or invalid 'fields' array in Salesforce metadata response");
        }
        
        // Iterate through fields
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
        
        // Free the document
        yyjson_doc_free(doc);
        
        // Add metadata to cache
        cache->AddToCache(object_name, fields);
    } catch (const std::exception &e) {
        throw std::runtime_error("Failed to parse Salesforce metadata: " + std::string(e.what()));
    }
    
    return fields;
}

// Helper function to process Salesforce API response and extract records
static std::pair<std::vector<SalesforceRecord>, std::string> ProcessSalesforceResponse(
    const std::string &response_string) {
    
    std::vector<SalesforceRecord> records;
    std::string next_records_url = "";
    
    // Parse JSON using yyjson
    yyjson_doc *doc = yyjson_read(response_string.c_str(), response_string.size(), YYJSON_READ_ALLOW_INVALID_UNICODE);
    if (!doc) {
        throw std::runtime_error("Failed to parse Salesforce response");
    }
    
    yyjson_val *root = yyjson_doc_get_root(doc);
    if (!root || yyjson_get_type(root) != YYJSON_TYPE_OBJ) {
        yyjson_doc_free(doc);
        throw std::runtime_error("Invalid JSON response from Salesforce");
    }
    
    // Get the records array
    yyjson_val *records_arr = yyjson_obj_get(root, "records");
    if (!records_arr || yyjson_get_type(records_arr) != YYJSON_TYPE_ARR) {
        yyjson_doc_free(doc);
        throw std::runtime_error("Missing or invalid 'records' array in Salesforce response");
    }
    
    // Add records
    size_t idx, max;
    yyjson_val *record;
    yyjson_arr_foreach(records_arr, idx, max, record) {
        // For each record, create a new document to ensure independent lifecycle
        char *record_str = yyjson_val_write(record, 0, nullptr);
        yyjson_doc *record_doc = yyjson_read(record_str, strlen(record_str), YYJSON_READ_ALLOW_INVALID_UNICODE);
        free(record_str);
        
        if (record_doc) {
            yyjson_val *record_root = yyjson_doc_get_root(record_doc);
            records.emplace_back(record_doc, record_root);
        }
    }
    
    // Get URL for next page, if any
    yyjson_val *next_records_url_val = yyjson_obj_get(root, "nextRecordsUrl");
    if (next_records_url_val && yyjson_is_str(next_records_url_val)) {
        next_records_url = yyjson_get_str(next_records_url_val);
    }
    
    // Free the document as we've copied the records we need
    yyjson_doc_free(doc);
    
    return {records, next_records_url};
}

// Function to execute SOQL query against Salesforce
static std::pair<std::vector<SalesforceRecord>, std::string> ExecuteSalesforceQuery(
    const std::string &query, 
    SalesforceCredentials &credentials) {

    // Ensure we have a valid token
    auto client = GetAuthorisedClient(credentials);
    
    // Use httplib's query parameter handling
    std::string url = "/services/data/v56.0/query";
    Params params;
    params.emplace("q", query);
    
    // Create empty headers - the GetAuthorisedClient already set default headers
    Headers headers;
    
    // Use httplib's Get method with query parameters and empty headers
    auto res = client.Get(url.c_str(), params, headers);
    
    if (res.error() != Error::Success) {
        throw std::runtime_error("Failed to execute Salesforce query: " + std::to_string(static_cast<int>(res.error())));
    }
    
    std::string response_string = res->body;
    long http_code = res->status;
    
    if (http_code == 401) {
        // Token expired, refresh and try again
        AuthenticateWithSalesforce(credentials);
        return ExecuteSalesforceQuery(query, credentials);
    } else if (http_code != 200) {
        throw std::runtime_error("Salesforce API returned error code: " + std::to_string(http_code) + "\nResponse: " + response_string);
    }
    
    try {
        return ProcessSalesforceResponse(response_string);
    } catch (const std::exception &e) {
        throw std::runtime_error("Failed to parse Salesforce query response: " + std::string(e.what()));
    }
}

static std::pair<std::vector<SalesforceRecord>, std::string> ContinueSalesforceQuery(
    const std::string &next_records_url, 
    SalesforceCredentials &credentials) {

    auto client = GetAuthorisedClient(credentials);
    
    auto res = client.Get(next_records_url.c_str());    
    if (res.error() != Error::Success) {
        throw std::runtime_error("Failed to continue Salesforce query: " + std::to_string(static_cast<int>(res.error())));
    }
    
    std::string response_string = res->body;
    long http_code = res->status;   
    
    if (http_code == 401) {
        AuthenticateWithSalesforce(credentials);
        return ContinueSalesforceQuery(next_records_url, credentials);
    } else if (http_code != 200) {
        throw std::runtime_error("Salesforce API returned error code: " + std::to_string(http_code) + "\nResponse: " + response_string);
    }
    
    try {
        return ProcessSalesforceResponse(response_string);
    } catch (const std::exception &e) {
        throw std::runtime_error("Failed to parse Salesforce query response: " + std::string(e.what()));
    }
}

// Convert Salesforce value to DuckDB value
static Value ConvertSalesforceValue(yyjson_val *value, const LogicalType &type, const std::string &field_name) {
    if (!value || yyjson_is_null(value)) {
        return Value(type);
    }
    
    switch (type.id()) {
        case LogicalTypeId::VARCHAR:
            if (yyjson_is_str(value)) {
                return Value(yyjson_get_str(value));
            }
            throw std::runtime_error("Expected string value for field: " + field_name);
        case LogicalTypeId::BOOLEAN:
            if (yyjson_is_bool(value)) {
                return Value::BOOLEAN(yyjson_get_bool(value));
            }
            throw std::runtime_error("Expected boolean value for field: " + field_name);
        case LogicalTypeId::INTEGER:
            if (yyjson_is_int(value)) {
                return Value::INTEGER((int32_t)yyjson_get_int(value));
            }
            throw std::runtime_error("Expected integer value for field: " + field_name);
        case LogicalTypeId::BIGINT:
            if (yyjson_is_int(value)) {
                return Value::BIGINT((int64_t)yyjson_get_int(value));
            }
            throw std::runtime_error("Expected integer value for field: " + field_name);
        case LogicalTypeId::DOUBLE:
            if (yyjson_is_num(value)) {
                return Value::DOUBLE(yyjson_get_num(value));
            }
            throw std::runtime_error("Expected numeric value for field: " + field_name);
        case LogicalTypeId::DATE: {
            if (yyjson_is_str(value)) {
                std::string date_str = yyjson_get_str(value);
                date_t date_val;
                bool special;
                idx_t pos = 0;
                DateCastResult result = Date::TryConvertDate(date_str.c_str(), date_str.length(), pos, date_val, special);
                if (result != DateCastResult::SUCCESS) {
                    throw std::runtime_error("Failed to convert Salesforce date value: " + date_str);
                }
                return Value::DATE(date_val);
            }
            throw std::runtime_error("Expected string date value for field: " + field_name);
        }
        case LogicalTypeId::TIMESTAMP: {
            if (yyjson_is_str(value)) {
                std::string ts_str = yyjson_get_str(value);
                timestamp_t ts_val;
                TimestampCastResult result = Timestamp::TryConvertTimestamp(ts_str.c_str(), ts_str.length(), ts_val);
                if (result != TimestampCastResult::SUCCESS) {
                    throw std::runtime_error("Failed to convert Salesforce timestamp value: " + ts_str);
                }
                return Value::TIMESTAMP(ts_val);
            }
            throw std::runtime_error("Expected string timestamp value for field: " + field_name);
        }       
        default:
            if (yyjson_is_str(value)) {
                return Value(yyjson_get_str(value));
            } else if (yyjson_is_num(value)) {
                return Value(std::to_string(yyjson_get_num(value)));
            } else if (yyjson_is_bool(value)) {
                return Value(yyjson_get_bool(value) ? "true" : "false");
            } else {
                return Value(type); // Return NULL for unsupported types
            }
    }
}

static void WriteRecordsToOutput(SalesforceScanState &state, DataChunk &output) {
    if (state.records.empty()) {
        return;
    }

    size_t count = std::min((idx_t)(state.records.size() - state.current_record_idx), (idx_t)(STANDARD_VECTOR_SIZE - state.current_chunk_idx));
    if (count == 0) {
        return;
    }
    
    for (idx_t col_idx = 0; col_idx < output.ColumnCount(); col_idx++) {
        auto &column = output.data[col_idx];
        auto &field = state.selected_fields[col_idx];
        
        // Process each row in the chunk
        for (idx_t row_idx = 0; row_idx < count; row_idx++) {
            const idx_t recordIndex = state.current_record_idx + row_idx;
            const idx_t outputIndex = state.current_chunk_idx + row_idx;
            
            const auto &record = state.records[recordIndex];
            
            try {
                yyjson_val *field_value = record.root;
                
                if (field_value) {
                    yyjson_val *field_val = yyjson_obj_get(field_value, field.name.c_str());
                    column.SetValue(outputIndex, ConvertSalesforceValue(field_val, field.duckdb_type, field.name));
                } else {
                    column.SetValue(outputIndex, Value(field.duckdb_type));
                }
            } catch (const std::exception &e) {
                // If conversion fails, set to NULL
                column.SetValue(outputIndex, Value(field.duckdb_type));
            }
        }
    }

    state.current_chunk_idx += count;

    state.current_record_idx += count;
    if (state.current_record_idx >= state.records.size()) {
        state.current_record_idx = 0;
        state.records.clear();
    }       
}

static std::string GenerateSOQLQuery(const SalesforceScanState &state, const SalesforceScanBindData &bind_data) {
    std::stringstream soql;
    soql << "SELECT ";

    if (state.count_only) {
        soql << "COUNT(Id) ";
    } else {
        auto first = true;
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

    return soql.str();
}

static void SalesforceObjectScan(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
    auto &bind_data = (SalesforceScanBindData &)*data.bind_data;
    auto &state = (SalesforceScanState &)*data.local_state;

    if (state.finished) {
        return;
    }

    state.current_chunk_idx = 0;

    try {
        if (state.next_records_url.empty() && state.records.empty()) {
            std::string soql = GenerateSOQLQuery(state, bind_data);
            auto [records, next_records_url] = ExecuteSalesforceQuery(soql, bind_data.credentials);
            state.records = std::move(records);
            state.next_records_url = std::move(next_records_url);
        }

        if (!state.records.empty() && state.current_record_idx < state.records.size()) {
            WriteRecordsToOutput(state, output);
        }

        while (!state.next_records_url.empty()) {
            auto [records, next_records_url] = ContinueSalesforceQuery(state.next_records_url, bind_data.credentials);
            state.records = std::move(records);
            state.next_records_url = std::move(next_records_url);
            
            WriteRecordsToOutput(state, output);
            if (state.current_chunk_idx >= STANDARD_VECTOR_SIZE) {
                break;
            }
        }
    } catch (const std::exception &e) {
        throw std::runtime_error("Failed to execute Salesforce query: " + std::string(e.what()));
    }

    if (state.count_only) {
        auto rowCount = output.GetValue(0, 0).GetValue<int64_t>();
        output.SetCardinality(rowCount);
    } else {
        output.SetCardinality(state.current_chunk_idx);
    }
    
    if (state.next_records_url.empty() && state.current_record_idx == 0) {
        state.finished = true;
    }
}

static unique_ptr<FunctionData> SalesforceObjectBind(ClientContext &context, TableFunctionBindInput &input,
    vector<LogicalType> &return_types, vector<string> &names) {
    
    auto bind_data = make_uniq<SalesforceScanBindData>();
    
    // Get the object name from the input
    bind_data->org_secret_name = input.inputs[0].GetValue<string>();
    bind_data->table_name = input.inputs[1].GetValue<string>();

    for (auto &kv : input.named_parameters) {
        if (kv.first == "row_limit") {
            try {
                bind_data->row_limit = kv.second.GetValue<uint32_t>();
            } catch (const std::exception& e) {
                throw InvalidInputException("Invalid value for 'row_limit' parameter. Expected an integer value.");
            }
        }
    }

    auto &secret_manager = SecretManager::Get(context);
    auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);
    auto secret_match = secret_manager.LookupSecret(transaction, bind_data->org_secret_name, "salesforce");
    
    if (!secret_match.HasMatch()) {
        throw InvalidInputException("No 'salesforce' secret found for '%s'. Please create a secret with 'CREATE SECRET' first.", bind_data->org_secret_name);
    }

    auto &secret = secret_match.GetSecret();
    if (secret.GetType() != "salesforce") {
        throw InvalidInputException("Invalid secret type. Expected 'salesforce', got '%s'", secret.GetType());
    }
    if (secret.GetProvider() != "access_token") {
        throw InvalidInputException("Invalid secret provider. Expected 'access_token', got '%s'", secret.GetProvider());
    }

    const auto *kv_secret = dynamic_cast<const KeyValueSecret*>(&secret);
    if (!kv_secret) {
        throw InvalidInputException("Invalid secret format for 'salesforce' secret");
    }

    // create Salesforce credentials from secret
    bind_data->credentials = SalesforceCredentials();

    Value secretValue;
    if (kv_secret->TryGetValue("login_url", secretValue)) {
        bind_data->credentials.login_url = secretValue.ToString();
    }
    if (kv_secret->TryGetValue("client_id", secretValue)) {
        bind_data->credentials.client_id = secretValue.ToString();
    } else {    
        throw InvalidInputException("Missing 'client_id' parameter in 'salesforce' secret");
    }
    if (kv_secret->TryGetValue("client_secret", secretValue)) {
        bind_data->credentials.client_secret = secretValue.ToString();
    } else {
        throw InvalidInputException("Missing 'client_secret' parameter in 'salesforce' secret");
    }
    if (kv_secret->TryGetValue("username", secretValue)) {
        bind_data->credentials.username = secretValue.ToString();
    } else {
        throw InvalidInputException("Missing 'username' parameter in 'salesforce' secret");
    }
    if (kv_secret->TryGetValue("password", secretValue)) {
        bind_data->credentials.password = secretValue.ToString();
    } else {
        throw InvalidInputException("Missing 'password' parameter in 'salesforce' secret");
    }
    if (kv_secret->TryGetValue("access_token", secretValue)) {
        bind_data->credentials.access_token = secretValue.ToString();
    }
    if (kv_secret->TryGetValue("instance_url", secretValue)) {
        bind_data->credentials.instance_url = secretValue.ToString();
    }
    if (kv_secret->TryGetValue("refresh_token", secretValue)) {
        bind_data->credentials.refresh_token = secretValue.ToString();
    }
    if (kv_secret->TryGetValue("token_expiry", secretValue)) {
        bind_data->credentials.token_expiry = secretValue.GetValue<uint32_t>();
    }
    
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

        if (input.column_ids.size() == 1 && input.column_ids[0] == UINT64_MAX) {
            scan_state->count_only = true;
            
            SalesforceField countField;
            countField.name = "expr0";
            countField.duckdb_type = LogicalType::BIGINT;
            countField.nillable = false;
            countField.type = "int";

            scan_state->selected_fields.push_back(countField);
        } else {
            for (const auto &col_idx : input.column_ids) {
                scan_state->selected_fields.push_back(bind_data.fields[col_idx]);
            }
        }
    } else {
        scan_state->selected_fields = bind_data.fields;
    }
    
    // Handle filter pushdown
    if (input.filters) {
        scan_state->where_clause = GenerateSOQLWhereClause(*scan_state, *input.filters);
    }

    return std::move(scan_state);
}

SalesforceObjectFunction::SalesforceObjectFunction() 
    : TableFunction(
        "salesforce_object", {LogicalType::VARCHAR, LogicalType::VARCHAR}, 
        SalesforceObjectScan, SalesforceObjectBind, 
        SalesforceObjectInitGlobalState, SalesforceObjectInitLocalState) {
    this->projection_pushdown = true;
    this->filter_pushdown = true;
    this->named_parameters["row_limit"] = LogicalType::INTEGER;
}

} // namespace duckdb 