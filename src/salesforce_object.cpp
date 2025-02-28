#include "salesforce_object.hpp"
#include "include/salesforce_metadata_cache.hpp"
#include "duckdb.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/common/types/date.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/planner/filter/optional_filter.hpp"
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
        // Create a deep copy of the document
        yyjson_read_flag flags = YYJSON_READ_ALLOW_INVALID_UNICODE;
        char *json_str = yyjson_val_write(other.root, 0, nullptr);
        doc = yyjson_read(json_str, strlen(json_str), flags);
        root = yyjson_doc_get_root(doc);
        free(json_str);
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
            
            // Create a deep copy of the document
            yyjson_read_flag flags = YYJSON_READ_ALLOW_INVALID_UNICODE;
            char *json_str = yyjson_val_write(other.root, 0, nullptr);
            doc = yyjson_read(json_str, strlen(json_str), flags);
            root = yyjson_doc_get_root(doc);
            free(json_str);
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
        return root == nullptr || duckdb_yyjson::yyjson_is_null(root);
    }
    
    // Get a field from the record
    yyjson_val* operator[](const char* key) const {
        return yyjson_obj_get(root, key);
    }
};

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
        if (!root || duckdb_yyjson::yyjson_get_type(root) != YYJSON_TYPE_OBJ) {
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
        
        credentials.access_token = duckdb_yyjson::yyjson_get_str(access_token);
        credentials.instance_url = duckdb_yyjson::yyjson_get_str(instance_url);
        
        // Set token expiry (typically 2 hours for Salesforce)
        credentials.token_expiry = time(nullptr) + 7200; // 2 hours
        
        if (refresh_token) {
            credentials.refresh_token = duckdb_yyjson::yyjson_get_str(refresh_token);
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
    
    return std::move(client);
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
    std::vector<SalesforceRecord> records;
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
        if (!root || duckdb_yyjson::yyjson_get_type(root) != YYJSON_TYPE_OBJ) {
            yyjson_doc_free(doc);
            throw std::runtime_error("Invalid JSON response from Salesforce");
        }
        
        // Get the fields array
        yyjson_val *fields_arr = yyjson_obj_get(root, "fields");
        if (!fields_arr || duckdb_yyjson::yyjson_get_type(fields_arr) != YYJSON_TYPE_ARR) {
            yyjson_doc_free(doc);
            throw std::runtime_error("Missing or invalid 'fields' array in Salesforce metadata response");
        }
        
        // Iterate through fields
        size_t idx, max;
        yyjson_val *field;
        yyjson_arr_foreach(fields_arr, idx, max, field) {
            if (duckdb_yyjson::yyjson_get_type(field) != YYJSON_TYPE_OBJ) {
                continue;
            }
            
            SalesforceField sf_field;
            
            yyjson_val *name = yyjson_obj_get(field, "name");
            yyjson_val *type = yyjson_obj_get(field, "type");
            yyjson_val *nillable = yyjson_obj_get(field, "nillable");
            
            if (name && type) {
                sf_field.name = duckdb_yyjson::yyjson_get_str(name);
                sf_field.type = duckdb_yyjson::yyjson_get_str(type);
                sf_field.nillable = nillable ? duckdb_yyjson::yyjson_get_bool(nillable) : false;
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
    const std::string &response_string, 
    yyjson_read_flag flags) {
    
    std::vector<SalesforceRecord> records;
    std::string next_records_url = "";
    
    // Parse JSON using yyjson
    yyjson_doc *doc = yyjson_read(response_string.c_str(), response_string.size(), flags);
    if (!doc) {
        throw std::runtime_error("Failed to parse Salesforce response");
    }
    
    yyjson_val *root = yyjson_doc_get_root(doc);
    if (!root || duckdb_yyjson::yyjson_get_type(root) != YYJSON_TYPE_OBJ) {
        yyjson_doc_free(doc);
        throw std::runtime_error("Invalid JSON response from Salesforce");
    }
    
    // Get the records array
    yyjson_val *records_arr = yyjson_obj_get(root, "records");
    if (!records_arr || duckdb_yyjson::yyjson_get_type(records_arr) != YYJSON_TYPE_ARR) {
        yyjson_doc_free(doc);
        throw std::runtime_error("Missing or invalid 'records' array in Salesforce response");
    }
    
    // Add records
    size_t idx, max;
    yyjson_val *record;
    yyjson_arr_foreach(records_arr, idx, max, record) {
        // For each record, create a new document to ensure independent lifecycle
        char *record_str = yyjson_val_write(record, 0, nullptr);
        yyjson_doc *record_doc = yyjson_read(record_str, strlen(record_str), flags);
        free(record_str);
        
        if (record_doc) {
            yyjson_val *record_root = yyjson_doc_get_root(record_doc);
            records.emplace_back(record_doc, record_root);
        }
    }
    
    // Get URL for next page, if any
    yyjson_val *next_records_url_val = yyjson_obj_get(root, "nextRecordsUrl");
    if (next_records_url_val && duckdb_yyjson::yyjson_is_str(next_records_url_val)) {
        next_records_url = duckdb_yyjson::yyjson_get_str(next_records_url_val);
    }
    
    // Free the document as we've copied the records we need
    yyjson_doc_free(doc);
    
    return {records, next_records_url};
}

// Function to execute SOQL query against Salesforce
static std::vector<SalesforceRecord> ExecuteSalesforceQuery(const std::string &query, SalesforceCredentials &credentials) {
    std::vector<SalesforceRecord> records;
    
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
        // Set up flags for yyjson
        yyjson_read_flag flags = YYJSON_READ_ALLOW_INVALID_UNICODE;
        
        // Process the initial response
        auto [initial_records, next_records_url] = ProcessSalesforceResponse(response_string, flags);
        records.insert(records.end(), initial_records.begin(), initial_records.end());
        
        // Handle pagination if needed
        while (!next_records_url.empty()) {
            auto next_client = GetAuthorisedClient(credentials);
            
            // Use httplib's Get method directly with the next_records_url
            auto next_res = next_client.Get(next_records_url.c_str());
            
            if (next_res.error() != Error::Success) {
                throw std::runtime_error("Failed to fetch next page: " + std::to_string(static_cast<int>(next_res.error())));
            }
            
            std::string next_response_string = next_res->body;
            long next_http_code = next_res->status;
            
            if (next_http_code == 401) {
                AuthenticateWithSalesforce(credentials);
                continue;
            } else if (next_http_code != 200) {
                throw std::runtime_error("Salesforce API returned error code: " + std::to_string(next_http_code) + 
                                        "\nResponse: " + next_response_string);
            }
            
            // Process the next page response
            auto [page_records, new_next_url] = ProcessSalesforceResponse(next_response_string, flags);
            records.insert(records.end(), page_records.begin(), page_records.end());
            next_records_url = new_next_url;
        }
    } catch (const std::exception &e) {
        throw std::runtime_error("Failed to parse Salesforce query response: " + std::string(e.what()));
    }
    
    return records;
}

// Convert Salesforce value to DuckDB value
static Value ConvertSalesforceValue(yyjson_val *value, const LogicalType &type, const std::string &field_name) {
    if (!value || duckdb_yyjson::yyjson_is_null(value)) {
        return Value(type);
    }
    
    switch (type.id()) {
        case LogicalTypeId::VARCHAR:
            if (duckdb_yyjson::yyjson_is_str(value)) {
                return Value(duckdb_yyjson::yyjson_get_str(value));
            }
            throw std::runtime_error("Expected string value for field: " + field_name);
        case LogicalTypeId::BOOLEAN:
            if (duckdb_yyjson::yyjson_is_bool(value)) {
                return Value::BOOLEAN(duckdb_yyjson::yyjson_get_bool(value));
            }
            throw std::runtime_error("Expected boolean value for field: " + field_name);
        case LogicalTypeId::INTEGER:
            if (duckdb_yyjson::yyjson_is_int(value)) {
                return Value::INTEGER((int32_t)duckdb_yyjson::yyjson_get_int(value));
            }
            throw std::runtime_error("Expected integer value for field: " + field_name);
        case LogicalTypeId::DOUBLE:
            if (duckdb_yyjson::yyjson_is_num(value)) {
                return Value::DOUBLE(duckdb_yyjson::yyjson_get_num(value));
            }
            throw std::runtime_error("Expected numeric value for field: " + field_name);
        case LogicalTypeId::DATE: {
            if (duckdb_yyjson::yyjson_is_str(value)) {
                std::string date_str = duckdb_yyjson::yyjson_get_str(value);
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
            if (duckdb_yyjson::yyjson_is_str(value)) {
                std::string ts_str = duckdb_yyjson::yyjson_get_str(value);
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
            if (duckdb_yyjson::yyjson_is_str(value)) {
                return Value(duckdb_yyjson::yyjson_get_str(value));
            } else if (duckdb_yyjson::yyjson_is_num(value)) {
                return Value(std::to_string(duckdb_yyjson::yyjson_get_num(value)));
            } else if (duckdb_yyjson::yyjson_is_bool(value)) {
                return Value(duckdb_yyjson::yyjson_get_bool(value) ? "true" : "false");
            } else {
                return Value(type); // Return NULL for unsupported types
            }
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
                yyjson_val *field_value = record.root;
                
                size_t dot_pos = field_name.find('.');
                while (dot_pos != std::string::npos) {
                    std::string parent = field_name.substr(0, dot_pos);
                    field_name = field_name.substr(dot_pos + 1);
                    
                    yyjson_val *parent_val = yyjson_obj_get(field_value, parent.c_str());
                    if (parent_val && !duckdb_yyjson::yyjson_is_null(parent_val)) {
                        field_value = parent_val;
                    } else {
                        // Parent field is null or doesn't exist
                        field_value = nullptr;
                        break;
                    }
                    
                    dot_pos = field_name.find('.');
                }
                
                if (field_value) {
                    yyjson_val *field_val = yyjson_obj_get(field_value, field_name.c_str());
                    column.SetValue(row_idx, ConvertSalesforceValue(field_val, field.duckdb_type, field.name));
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