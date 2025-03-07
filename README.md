# DuckDB Salesforce Extension

This extension allows you to query Salesforce data directly from DuckDB, enabling seamless integration between your Salesforce instance and DuckDB's powerful analytical capabilities.

## WARNING!!!
This code has been heavily generated using Claude 3.7 with some hand holding/tweaks from a non C++ developer. I fully expect that it is a horrorshow to a seasoned C++ engineer. It is working well enough for my purposes currently. It's a work-in-progress and will need a lot more resilience & testing so use at your own risk!

## Features

- **Direct Salesforce Object Querying**: Query Salesforce objects as if they were database tables
- **Secure Credential Management**: Store and manage Salesforce credentials securely using DuckDB's Secret Manager
- **Automatic Authentication**: Handles OAuth 2.0 authentication flow with automatic token refresh
- **Metadata Caching**: Caches object metadata to improve performance
- **Filter Pushdown**: Pushes filters to Salesforce API for efficient querying
- **Projection Pushdown**: Only retrieves the columns you need
- **Pagination Handling**: Automatically handles Salesforce API pagination for large result sets

## Usage

### Installation

Note: For the moment this is a unsigned extension and will DuckDB will only load it if allow_unsigned_extensions is enabled.


```sql
INSTALL salesforce;
LOAD salesforce;
```

### Setting up Salesforce Credentials

Only the user/password OAuth Flow is currently supported. More flows need to be integrated.

Store your Salesforce credentials securely using DuckDB's Secret Manager:

```sql
CREATE OR REPLACE PERSISTENT SECRET dev (
    TYPE salesforce,
    LOGIN_URL 'https://test.salesforce.com',
    CLIENT_ID '<your client id>',
    CLIENT_SECRET '<your client secret>',
    USERNAME '<your username>',
    PASSWORD '<your password+security token>');

```

### Querying Salesforce Objects

Once your credentials are set up, you can query Salesforce objects:

```sql
-- Query all fields from Account
SELECT * FROM salesforce_object('my_salesforce_org', 'Account');

-- Query specific fields with a limit
SELECT Id, Name, Industry 
FROM salesforce_object('my_salesforce_org', 'Account', row_limit=100);

-- Apply filters (these will be pushed down to Salesforce)
SELECT Id, Name, AnnualRevenue
FROM salesforce_object('my_salesforce_org', 'Account')
WHERE Industry = 'Technology' AND AnnualRevenue > 1000000;

-- Join with local data
SELECT a.Name, a.Industry, o.Amount
FROM salesforce_object('my_salesforce_org', 'Account') a
JOIN salesforce_object('my_salesforce_org', 'Opportunity') o
  ON a.Id = o.AccountId
WHERE o.StageName = 'Closed Won';
```
Replacement scans are also supported so the following simpler syntax will also work:

```sql
-- Query all fields from Account
SELECT * FROM my_salesforce_org.Account;


-- Apply filters (these will be pushed down to Salesforce)
SELECT Id, Name, AnnualRevenue
FROM my_salesforce_org.Account
WHERE Industry = 'Technology' AND AnnualRevenue > 1000000;

-- Join with local data
SELECT a.Name, a.Industry, o.Amount
FROM my_salesforce_org.Account a
JOIN my_salesforce_org.Opportunity o
  ON a.Id = o.AccountId
WHERE o.StageName = 'Closed Won';
```

## Technical Details

### Data Type Mapping

The extension automatically maps Salesforce data types to appropriate DuckDB types:

| Salesforce Type | DuckDB Type |
|-----------------|-------------|
| string, id, reference | VARCHAR |
| boolean | BOOLEAN |
| int, currency | INTEGER |
| double, percent | DOUBLE |
| date | DATE |
| datetime | TIMESTAMP |
| *other types* | VARCHAR |

### Performance Considerations

- **Metadata Caching**: Object metadata is cached for 1 hour by default to reduce API calls
- **Filter Pushdown**: WHERE clauses are converted to SOQL filters and executed on the Salesforce server
- **Projection Pushdown**: Only requested columns are retrieved from Salesforce
- **Pagination**: Results are automatically paginated for large result sets
- **Row Limits**: Use the `row_limit` parameter to limit the number of rows returned

### Limitations

- Complex SOQL features like aggregate functions are not supported
- Relationship queries are limited to direct field access (e.g., `Owner.Name`)
- Updates and inserts to Salesforce are not supported (read-only)
- Binary fields (base64) are not supported
- Geolocation fields are not supported

## Building from Source

### Managing dependencies
DuckDB extensions uses VCPKG for dependency management. Enabling VCPKG is very simple: follow the [installation instructions](https://vcpkg.io/en/getting-started) or just run the following:
```shell
git clone https://github.com/Microsoft/vcpkg.git
./vcpkg/bootstrap-vcpkg.sh
export VCPKG_TOOLCHAIN_PATH=`pwd`/vcpkg/scripts/buildsystems/vcpkg.cmake
```

### Build steps
To build the extension, run:
```sh
GEN=ninja make
```

The main binaries that will be built are:
```sh
./build/release/duckdb
./build/release/test/unittest
./build/release/extension/salesforce/salesforce.duckdb_extension
```

