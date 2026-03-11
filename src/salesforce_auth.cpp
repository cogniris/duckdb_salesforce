#include "salesforce_auth.hpp"

#include "yyjson.hpp"

using namespace duckdb_yyjson;

namespace duckdb {

std::string TruncateForError(const std::string &response) {
	if (response.size() <= MAX_ERROR_RESPONSE_LENGTH) {
		return response;
	}
	return response.substr(0, MAX_ERROR_RESPONSE_LENGTH) + "... (truncated)";
}

void ConfigureHttpClient(Client &client) {
	client.enable_server_certificate_verification(true);
	client.set_connection_timeout(HTTP_CONNECT_TIMEOUT_SEC);
	client.set_read_timeout(HTTP_READ_TIMEOUT_SEC);
}

bool AuthenticateWithSalesforce(SalesforceCredentials &credentials) {
	Client client(credentials.login_url.c_str());
	ConfigureHttpClient(client);

	Params form_params;
	form_params.emplace("grant_type", "password");
	form_params.emplace("client_id", credentials.client_id);
	form_params.emplace("client_secret", credentials.client_secret);
	form_params.emplace("username", credentials.username);
	form_params.emplace("password", credentials.password);

	std::string url = "/services/oauth2/token";

	auto res = client.Post(url.c_str(), form_params);

	if (res.error() != Error::Success) {
		throw std::runtime_error("Failed to authenticate with Salesforce: " + std::to_string(static_cast<int>(res.error())));
	}

	std::string response_string = res->body;
	long http_code = res->status;

	if (http_code != 200) {
		throw std::runtime_error("Salesforce authentication failed with code: " + std::to_string(http_code) +
		                         "\nResponse: " + TruncateForError(response_string));
	}

	try {
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

		yyjson_val *access_token = yyjson_obj_get(root, "access_token");
		yyjson_val *instance_url = yyjson_obj_get(root, "instance_url");
		yyjson_val *refresh_token = yyjson_obj_get(root, "refresh_token");

		if (!access_token || !instance_url) {
			yyjson_doc_free(doc);
			throw std::runtime_error("Missing required fields in Salesforce authentication response");
		}

		credentials.access_token = yyjson_get_str(access_token);
		credentials.instance_url = yyjson_get_str(instance_url);

		yyjson_val *issued_at = yyjson_obj_get(root, "issued_at");
		if (issued_at && yyjson_is_str(issued_at)) {
			time_t issued_time = std::stoll(yyjson_get_str(issued_at)) / 1000;
			credentials.token_expiry = issued_time + 7200;
		} else {
			credentials.token_expiry = time(nullptr) + 7200;
		}

		if (refresh_token) {
			credentials.refresh_token = yyjson_get_str(refresh_token);
		}

		yyjson_doc_free(doc);

		return true;
	} catch (const std::exception &e) {
		throw std::runtime_error("Failed to parse Salesforce authentication response: " + std::string(e.what()));
	}
}

void EnsureValidToken(SalesforceCredentials &credentials) {
	if (credentials.access_token.empty() || time(nullptr) >= credentials.token_expiry) {
		AuthenticateWithSalesforce(credentials);
	}
}

Client GetAuthorisedClient(SalesforceCredentials &credentials) {
	EnsureValidToken(credentials);
	Client client(credentials.instance_url.c_str());
	ConfigureHttpClient(client);
	client.set_bearer_token_auth(credentials.access_token);
	client.set_default_headers({
		{"Content-Type", "application/json"}
	});

	return client;
}

void PopulateCredentialsFromSecret(const KeyValueSecret &kv_secret, SalesforceCredentials &credentials) {
	Value secretValue;

	if (kv_secret.TryGetValue("login_url", secretValue)) {
		credentials.login_url = secretValue.ToString();
	}
	if (kv_secret.TryGetValue("client_id", secretValue)) {
		credentials.client_id = secretValue.ToString();
	} else {
		throw InvalidInputException("Missing 'client_id' parameter in 'salesforce' secret");
	}
	if (kv_secret.TryGetValue("client_secret", secretValue)) {
		credentials.client_secret = secretValue.ToString();
	} else {
		throw InvalidInputException("Missing 'client_secret' parameter in 'salesforce' secret");
	}
	if (kv_secret.TryGetValue("username", secretValue)) {
		credentials.username = secretValue.ToString();
	} else {
		throw InvalidInputException("Missing 'username' parameter in 'salesforce' secret");
	}
	if (kv_secret.TryGetValue("password", secretValue)) {
		credentials.password = secretValue.ToString();
	} else {
		throw InvalidInputException("Missing 'password' parameter in 'salesforce' secret");
	}
	if (kv_secret.TryGetValue("access_token", secretValue)) {
		credentials.access_token = secretValue.ToString();
	}
	if (kv_secret.TryGetValue("instance_url", secretValue)) {
		credentials.instance_url = secretValue.ToString();
	}
	if (kv_secret.TryGetValue("refresh_token", secretValue)) {
		credentials.refresh_token = secretValue.ToString();
	}
	if (kv_secret.TryGetValue("api_version", secretValue)) {
		credentials.api_version = secretValue.ToString();
	}
	if (kv_secret.TryGetValue("token_expiry", secretValue)) {
		credentials.token_expiry = secretValue.GetValue<uint32_t>();
	}
}

} // namespace duckdb
