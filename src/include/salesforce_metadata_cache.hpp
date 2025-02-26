#pragma once

#include "duckdb.hpp"
#include <vector>
#include <string>
#include <unordered_map>
#include <mutex>

namespace duckdb {

// Structure to hold field metadata
struct SalesforceField {
    std::string name;
    std::string type;
    bool nillable;
    LogicalType duckdb_type;
};

// Salesforce data type mapping to DuckDB types
LogicalType MapSalesforceType(const std::string &sf_type);

// Class to cache Salesforce object metadata
class SalesforceMetadataCache {
private:
    // Singleton instance
    static SalesforceMetadataCache* instance;
    static std::mutex instance_mutex;
    
    // Cache storage: object_name -> (metadata, timestamp)
    std::unordered_map<std::string, std::pair<std::vector<SalesforceField>, time_t>> cache;
    std::mutex cache_mutex;
    
    // Cache expiration time in seconds (default: 1 hour)
    time_t cache_expiry_seconds = 3600;
    
    // Private constructor for singleton
    SalesforceMetadataCache() {}
    
public:
    // Delete copy constructor and assignment operator
    SalesforceMetadataCache(const SalesforceMetadataCache&) = delete;
    SalesforceMetadataCache& operator=(const SalesforceMetadataCache&) = delete;
    
    // Get singleton instance
    static SalesforceMetadataCache* GetInstance();
    
    // Set cache expiration time
    void SetCacheExpirySeconds(time_t seconds);
    
    // Add metadata to cache
    void AddToCache(const std::string& object_name, const std::vector<SalesforceField>& metadata);
    
    // Check if metadata is in cache and not expired
    bool IsInCache(const std::string& object_name);
    
    // Get metadata from cache
    std::vector<SalesforceField> GetFromCache(const std::string& object_name);
    
    // Clear the cache
    void ClearCache();
    
    // Clear a specific object from cache
    void ClearFromCache(const std::string& object_name);
};

} // namespace duckdb 