#include "include/salesforce_metadata_cache.hpp"
#include <time.h>

namespace duckdb {

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

// Initialize static members
SalesforceMetadataCache* SalesforceMetadataCache::instance = nullptr;
std::mutex SalesforceMetadataCache::instance_mutex;

// Implementation of SalesforceMetadataCache methods
SalesforceMetadataCache* SalesforceMetadataCache::GetInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex);
    if (instance == nullptr) {
        instance = new SalesforceMetadataCache();
    }
    return instance;
}

void SalesforceMetadataCache::SetCacheExpirySeconds(time_t seconds) {
    std::lock_guard<std::mutex> lock(cache_mutex);
    cache_expiry_seconds = seconds;
}

void SalesforceMetadataCache::AddToCache(const std::string& object_name, const std::vector<SalesforceField>& metadata) {
    std::lock_guard<std::mutex> lock(cache_mutex);
    cache[object_name] = std::make_pair(metadata, time(nullptr));
}

bool SalesforceMetadataCache::IsInCache(const std::string& object_name) {
    std::lock_guard<std::mutex> lock(cache_mutex);
    auto it = cache.find(object_name);
    if (it == cache.end()) {
        return false;
    }
    
    // Check if cache entry is expired
    time_t now = time(nullptr);
    time_t cache_time = it->second.second;
    return (now - cache_time) < cache_expiry_seconds;
}

std::vector<SalesforceField> SalesforceMetadataCache::GetFromCache(const std::string& object_name) {
    std::lock_guard<std::mutex> lock(cache_mutex);
    auto it = cache.find(object_name);
    if (it != cache.end()) {
        return it->second.first;
    }
    return std::vector<SalesforceField>();
}

void SalesforceMetadataCache::ClearCache() {
    std::lock_guard<std::mutex> lock(cache_mutex);
    cache.clear();
}

void SalesforceMetadataCache::ClearFromCache(const std::string& object_name) {
    std::lock_guard<std::mutex> lock(cache_mutex);
    cache.erase(object_name);
}

} // namespace duckdb 