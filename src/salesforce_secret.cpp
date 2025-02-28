#include "duckdb/common/types.hpp"
#include "duckdb/common/unique_ptr.hpp"
#include "duckdb/main/extension_util.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "salesforce_secret.hpp"

namespace duckdb {
constexpr auto COMMON_OPTIONS = {
    "login_url", "client_id", "client_secret",
    "username", "password",
    "access_token", "refresh_token", "token_expiry"
};

static void CopySecret(const std::string &key, const CreateSecretInput &input, KeyValueSecret &result) {
	auto val = input.options.find(key);

	if (val != input.options.end()) {
		result.secret_map[key] = val->second;
	}
}

static unique_ptr<BaseSecret> CreateSecretFromAccessToken(ClientContext &context, CreateSecretInput &input) {
	auto result = make_uniq<KeyValueSecret>(input.scope, input.type, input.provider, input.name);

	// Manage common option that all secret type share
	for (const auto *key : COMMON_OPTIONS) {
		CopySecret(key, input, *result);
	}

	return std::move(result);
}

static void RegisterCommonSecretParameters(CreateSecretFunction &function) {
	function.named_parameters["client_id"] = LogicalType::VARCHAR;
	function.named_parameters["client_secret"] = LogicalType::VARCHAR;
	function.named_parameters["username"] = LogicalType::VARCHAR;
	function.named_parameters["password"] = LogicalType::VARCHAR;
	function.named_parameters["login_url"] = LogicalType::VARCHAR;
    function.named_parameters["access_token"] = LogicalType::VARCHAR;
    function.named_parameters["refresh_token"] = LogicalType::VARCHAR;
    function.named_parameters["token_expiry"] = LogicalType::INTEGER;
}

void CreateSalesforceSecretFunctions::Register(DatabaseInstance &instance) {
	string type = "salesforce";

	// Register the new type
	SecretType secret_type;
	secret_type.name = type;
	secret_type.deserializer = KeyValueSecret::Deserialize<KeyValueSecret>;
	secret_type.default_provider = "access_token";
	ExtensionUtil::RegisterSecretType(instance, secret_type);

	// Register the access_token secret provider
	CreateSecretFunction access_token_function = {type, "access_token", CreateSecretFromAccessToken};
	access_token_function.named_parameters["access_token"] = LogicalType::VARCHAR;
	RegisterCommonSecretParameters(access_token_function);
	ExtensionUtil::RegisterFunction(instance, access_token_function);
}

} // namespace duckdb