// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

namespace cpp impala
namespace java com.cloudera.impala.thrift

include "ExecStats.thrift"
include "cli_service.thrift"

// The summary of a DML statement.
struct TDmlResult {
  // Number of modified rows per partition. Only applies to HDFS and Kudu tables.
  // The keys represent partitions to create, coded as k1=v1/k2=v2/k3=v3..., with
  // the root in an unpartitioned table being the empty string.
  1: required map<string, i64> rows_modified
  3: optional map<string, i64> rows_deleted

  // Number of row operations attempted but not completed due to non-fatal errors
  // reported by the storage engine that Impala treats as warnings. Only applies to Kudu
  // tables. This includes errors due to duplicate/missing primary keys, nullability
  // constraint violations, and primary keys in uncovered partition ranges.
  // TODO: Provide a detailed breakdown of these counts by error. IMPALA-4416.
  2: optional i64 num_row_errors
}

// Response from a call to PingImpalaService
struct TPingImpalaServiceResp {
  // The Impala service's version string.
  1: string version

  // The Impalad's webserver address.
  2: string webserver_address
}

// Parameters for a ResetTable request which will invalidate a table's metadata.
// DEPRECATED.
struct TResetTableReq {
  // Name of the table's parent database.
  1: required string db_name

  // Name of the table.
  2: required string table_name
}

// PingImpalaHS2Service() - ImpalaHiveServer2Service version.
// Pings the Impala server to confirm that the server is alive and the session identified
// by 'sessionHandle' is open. Returns metadata about the server. This exists separate
// from the base HS2 GetInfo() methods because not all relevant metadata is accessible
// through GetInfo().
struct TPingImpalaHS2ServiceReq {
  1: required cli_service.TSessionHandle sessionHandle
}

struct TPingImpalaHS2ServiceResp {
  1: required cli_service.TStatus status

  // The Impala service's version string.
  2: optional string version

  // The Impalad's webserver address.
  3: optional string webserver_address

  // The Impalad's local monotonic time
  4: optional i64 timestamp
}

// CloseImpalaOperation()
//
// Extended version of CloseOperation() that, if the operation was a DML
// operation, returns statistics about the operation.
struct TCloseImpalaOperationReq {
  1: required cli_service.TOperationHandle operationHandle
}

struct TCloseImpalaOperationResp {
  1: required cli_service.TStatus status

  // Populated if the operation was a DML operation.
  2: optional TDmlResult dml_result
}

// Impala HiveServer2 service

struct TGetExecSummaryReq {
  1: optional cli_service.TOperationHandle operationHandle

  2: optional cli_service.TSessionHandle sessionHandle

  // If true, returns the summaries of all query attempts. A TGetExecSummaryResp
  // always returns the profile for the most recent query attempt, regardless of the
  // query id specified. Clients should set this to true if they want to retrieve the
  // summaries of all query attempts (including the failed ones).
  3: optional bool include_query_attempts = false
}

struct TGetExecSummaryResp {
  1: required cli_service.TStatus status

  2: optional ExecStats.TExecSummary summary

  // A list of all summaries of the failed query attempts.
  3: optional list<ExecStats.TExecSummary> failed_summaries
}


service ImpalaHiveServer2Service extends cli_service.TCLIService {
  // Returns the exec summary for the given query. The exec summary is only valid for
  // queries that execute with Impala's backend, i.e. QUERY, DML and COMPUTE_STATS
  // queries. Otherwise a default-initialized TExecSummary is returned for
  // backwards-compatibility with impala-shell - see IMPALA-9729.
  TGetExecSummaryResp GetExecSummary(1:TGetExecSummaryReq req);

  // Client calls this RPC to verify that the server is an ImpalaService. Returns the
  // server version.
  TPingImpalaHS2ServiceResp PingImpalaHS2Service(1:TPingImpalaHS2ServiceReq req);

  // Same as HS2 CloseOperation but can return additional information.
  TCloseImpalaOperationResp CloseImpalaOperation(1:TCloseImpalaOperationReq req);
}
