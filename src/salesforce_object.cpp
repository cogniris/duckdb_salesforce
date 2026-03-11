#include "salesforce_object.hpp"
#include "salesforce_soql.hpp"
#include "duckdb/main/secret/secret_manager.hpp"

namespace duckdb {

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

		for (idx_t row_idx = 0; row_idx < count; row_idx++) {
			const idx_t recordIndex = state.current_record_idx + row_idx;
			const idx_t outputIndex = state.current_chunk_idx + row_idx;

			const auto &record = state.records[recordIndex];

			yyjson_val *field_value = record.root;

			if (field_value) {
				yyjson_val *field_val = yyjson_obj_get(field_value, field.name.c_str());
				column.SetValue(outputIndex, ConvertSalesforceValue(field_val, field.duckdb_type));
			} else {
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

static void SalesforceObjectScan(ClientContext & /*context*/, TableFunctionInput &data, DataChunk &output) {
	auto &bind_data = (SalesforceScanBindData &)*data.bind_data;
	auto &state = (SalesforceScanState &)*data.local_state;

	if (state.finished) {
		return;
	}

	state.current_chunk_idx = 0;

	try {
		if (state.next_records_url.empty() && state.records.empty()) {
			std::string soql = GenerateSOQLQuery(state, bind_data);
			auto [records, next_records_url] = ExecuteSalesforceQuery(soql, bind_data.credentials, bind_data.credentials_mutex);
			state.records = std::move(records);
			state.next_records_url = std::move(next_records_url);
		}

		if (!state.records.empty() && state.current_record_idx < state.records.size()) {
			WriteRecordsToOutput(state, output);
		}

		while (!state.next_records_url.empty()) {
			auto [records, next_records_url] = ContinueSalesforceQuery(state.next_records_url, bind_data.credentials, bind_data.credentials_mutex);
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
		output.SetCardinality(1);
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
	auto secret_entry = secret_manager.GetSecretByName(transaction, bind_data->org_secret_name);

	if (!secret_entry) {
		throw InvalidInputException("No secret found with name '%s'. Please create a secret with 'CREATE SECRET' first.", bind_data->org_secret_name);
	}

	auto &secret = *secret_entry->secret;
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

	bind_data->credentials = SalesforceCredentials();
	PopulateCredentialsFromSecret(*kv_secret, bind_data->credentials);

	try {
		bind_data->fields = FetchSalesforceObjectMetadata(bind_data->table_name, bind_data->credentials);

		for (const auto &field : bind_data->fields) {
			return_types.push_back(field.duckdb_type);
			names.push_back(field.name);
		}
	} catch (const std::exception &e) {
		throw BinderException("Failed to bind Salesforce object: " + std::string(e.what()));
	}

	return std::move(bind_data);
}

static unique_ptr<GlobalTableFunctionState> SalesforceObjectInitGlobalState(ClientContext & /*context*/,
	TableFunctionInitInput & /*input*/) {
	return nullptr;
}

static unique_ptr<LocalTableFunctionState> SalesforceObjectInitLocalState(ExecutionContext & /*context*/,
	TableFunctionInitInput &input,
	GlobalTableFunctionState * /*global_state*/) {

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
				if (col_idx >= bind_data.fields.size()) {
					throw InternalException("Column index %llu out of range (object has %llu fields)", col_idx, bind_data.fields.size());
				}
				scan_state->selected_fields.push_back(bind_data.fields[col_idx]);
			}
		}
	} else {
		scan_state->selected_fields = bind_data.fields;
	}

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
