#pragma once

#include "duckdb.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include <string>
#include <mutex>
#include <functional>

// Define OpenSSL support before including httplib
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.hpp"

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

	// Salesforce API version
	std::string api_version = "v62.0";

	// Token information (will be populated during authentication)
	std::string access_token;
	std::string instance_url;
	std::string refresh_token;
	time_t token_expiry = 0;
};

static constexpr time_t HTTP_CONNECT_TIMEOUT_SEC = 30;
static constexpr time_t HTTP_READ_TIMEOUT_SEC = 300;
static constexpr size_t MAX_ERROR_RESPONSE_LENGTH = 512;

std::string TruncateForError(const std::string &response);
void ConfigureHttpClient(Client &client);
bool AuthenticateWithSalesforce(SalesforceCredentials &credentials);
void EnsureValidToken(SalesforceCredentials &credentials);
Client GetAuthorisedClient(SalesforceCredentials &credentials);

// Common helper: make an authenticated GET request with 401 retry.
// RequestFn signature: Result(Client&)
template <typename RequestFn>
std::string MakeAuthenticatedGet(
	SalesforceCredentials &credentials,
	std::mutex &credentials_mutex,
	const std::string &error_context,
	RequestFn request_fn) {

	Client client = [&]() {
		std::lock_guard<std::mutex> lock(credentials_mutex);
		return GetAuthorisedClient(credentials);
	}();

	auto res = request_fn(client);
	if (res.error() != Error::Success) {
		throw std::runtime_error("Failed to " + error_context + ": " + std::to_string(static_cast<int>(res.error())));
	}

	std::string response_string = res->body;
	long http_code = res->status;

	if (http_code == 401) {
		std::lock_guard<std::mutex> lock(credentials_mutex);
		AuthenticateWithSalesforce(credentials);
		auto retry_client = GetAuthorisedClient(credentials);
		auto retry_res = request_fn(retry_client);
		if (retry_res.error() != Error::Success) {
			throw std::runtime_error("Failed to " + error_context + " after token refresh: " + std::to_string(static_cast<int>(retry_res.error())));
		}
		response_string = retry_res->body;
		http_code = retry_res->status;
		if (http_code == 401) {
			throw std::runtime_error("Salesforce authentication failed after token refresh (HTTP 401)");
		}
	}

	if (http_code != 200) {
		throw std::runtime_error("Salesforce API returned error code: " + std::to_string(http_code) + "\nResponse: " + TruncateForError(response_string));
	}

	return response_string;
}

// Extract credentials from a DuckDB KeyValueSecret
void PopulateCredentialsFromSecret(const KeyValueSecret &kv_secret, SalesforceCredentials &credentials);

} // namespace duckdb
