#include "salesforce_soql.hpp"
#include "salesforce_object.hpp"

#include "duckdb/common/types/date.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/planner/filter/optional_filter.hpp"

namespace duckdb {

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
		return LogicalType::VARCHAR;
	}
}

Value ConvertSalesforceValue(yyjson_val *value, const LogicalType &type) {
	if (!value || yyjson_is_null(value)) {
		return Value(type);
	}

	switch (type.id()) {
		case LogicalTypeId::VARCHAR:
			if (yyjson_is_str(value)) {
				return Value(yyjson_get_str(value));
			}
			return Value(type);
		case LogicalTypeId::BOOLEAN:
			if (yyjson_is_bool(value)) {
				return Value::BOOLEAN(yyjson_get_bool(value));
			}
			return Value(type);
		case LogicalTypeId::INTEGER:
			if (yyjson_is_int(value)) {
				return Value::INTEGER((int32_t)yyjson_get_int(value));
			}
			return Value(type);
		case LogicalTypeId::BIGINT:
			if (yyjson_is_int(value)) {
				return Value::BIGINT((int64_t)yyjson_get_int(value));
			}
			return Value(type);
		case LogicalTypeId::DOUBLE:
			if (yyjson_is_num(value)) {
				return Value::DOUBLE(yyjson_get_num(value));
			}
			return Value(type);
		case LogicalTypeId::DATE: {
			if (yyjson_is_str(value)) {
				std::string date_str = yyjson_get_str(value);
				date_t date_val;
				bool special;
				idx_t pos = 0;
				DateCastResult result = Date::TryConvertDate(date_str.c_str(), date_str.length(), pos, date_val, special);
				if (result != DateCastResult::SUCCESS) {
					return Value(type);
				}
				return Value::DATE(date_val);
			}
			return Value(type);
		}
		case LogicalTypeId::TIMESTAMP: {
			if (yyjson_is_str(value)) {
				std::string ts_str = yyjson_get_str(value);
				timestamp_t ts_val;
				TimestampCastResult result = Timestamp::TryConvertTimestamp(ts_str.c_str(), ts_str.length(), ts_val, false);
				if (result != TimestampCastResult::SUCCESS) {
					return Value(type);
				}
				return Value::TIMESTAMP(ts_val);
			}
			return Value(type);
		}
		default:
			if (yyjson_is_str(value)) {
				return Value(yyjson_get_str(value));
			} else if (yyjson_is_num(value)) {
				return Value(std::to_string(yyjson_get_num(value)));
			} else if (yyjson_is_bool(value)) {
				return Value(yyjson_get_bool(value) ? "true" : "false");
			} else {
				return Value(type);
			}
	}
}

std::string GenerateSOQLQuery(const SalesforceScanState &state, const SalesforceScanBindData &bind_data) {
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

	if (!state.where_clause.empty()) {
		soql << " WHERE " << state.where_clause;
	}

	if (bind_data.row_limit > 0) {
		soql << " LIMIT " << bind_data.row_limit;
	}

	return soql.str();
}

static void GenerateSOQLWhereClauseInternal(const std::string &column_name, TableFilter *filter, std::stringstream &where_clause) {
	switch (filter->filter_type) {
		case duckdb::TableFilterType::CONSTANT_COMPARISON:
		case duckdb::TableFilterType::IN_FILTER: {
			where_clause << filter->ToString(column_name).c_str();
			return;
		}
		case duckdb::TableFilterType::IS_NULL: {
			where_clause << column_name << " = null";
			return;
		}
		case duckdb::TableFilterType::IS_NOT_NULL: {
			where_clause << column_name << " != null";
			return;
		}
		case duckdb::TableFilterType::CONJUNCTION_OR:
		case duckdb::TableFilterType::CONJUNCTION_AND: {
			auto conjunction_filter = reinterpret_cast<duckdb::ConjunctionFilter *>(filter);
			where_clause << "(";
			if (conjunction_filter->child_filters.size() > 1) {
				for (idx_t i = 0; i < conjunction_filter->child_filters.size() - 1; i++) {
					GenerateSOQLWhereClauseInternal(column_name, conjunction_filter->child_filters[i].get(), where_clause);
					where_clause << (filter->filter_type == duckdb::TableFilterType::CONJUNCTION_OR ? " OR " : " AND ");
				}
			}
			GenerateSOQLWhereClauseInternal(column_name, conjunction_filter->child_filters.back().get(), where_clause);
			where_clause << ")";
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

std::string GenerateSOQLWhereClause(const SalesforceScanState &state, const TableFilterSet &filterSet) {
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

} // namespace duckdb
