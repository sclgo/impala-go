# Design notes

## Non-goals

The goal of this library is to provide a database/sql driver and metadata/schema API for Apache Impala.
The following related capabilities are non-goals for now. This may change based on demand so feel free to open
an issue demanding it. It would need to gather some number of votes to become a goal though.

- **provide a query API to Impala beyond `database/sql`**
  While the `database/sql` API does not expose the full capabilities of Impala e.g. async queries,
  Go users of these features are better off calling the Impala API directly (generating their own Thrift bindings),
  than using this library. If some of the code in `/internal` is valuable,
  then copy it because this library maintains API stability and follows semantic versioning only for the public code.
  ["A little copying is better than a little dependency."](https://go-proverbs.github.io/)
- **fully support Hive, in addition to Impala**
  As discussed below, this library is somewhat compatible with Hive, not just Impala. Nevertheless,
  testing this library against Hive and resolving issues that occur only with Hive is not a goal.
  Hive users are recommended to use [sqlflow.org/gohive](https://sqlflow.org/gohive).

## Impala driver or Hive driver

Impala [implements](https://impala.apache.org/docs/build/asf-site-html/topics/impala_client.html) the Hive remote API,
called [Hive Server 2](https://cwiki.apache.org/confluence/display/hive/hiveserver2+overview).
As a result, all Hive clients are compatible with Impala to some extent and vice versa.
For example, the Apache Impala OSS documentation even recommends that Java applications
[use the Hive JDBC driver](https://impala.apache.org/docs/build/asf-site-html/topics/impala_jdbc.html).

There is a Go database/sql client for Hive - https://sqlflow.org/gohive. However, in my testing,
it is a poor client for Impala. For example,

- **The Hive driver does not show errors, reported by Impala.**
  The root cause is that the driver prints only `Respose.Status.InfoMessages[]`,
  while Impala populates either `Response.Status.ErrorMessage` or `Response.State.ErrorMessage`
  [depending on the error](https://github.com/sclgo/impala-go/blob/657aa1d/internal/isql/connection_test.go#L139).
- **Non-trivial Impala DML statements don't work with the Hive driver.**
  The driver does not support async statement execution, while Impala HS2 server
  [does not support](https://github.com/cloudera/impyla/issues/157#issuecomment-164090890)
  sync execution. Impala ignores the RunAsync field in `TExecuteStatementReq` and assumes it is `true`,
  even though the default is `false`. As a result, the Hive driver doesn't wait for
  DML statement to complete and closes them immediately, cancelling them in the process.
  In contrast, the Hive JDBC driver always uses async execution
  [by default](https://issues.apache.org/jira/browse/HIVE-5232) so it works with Impala.

Outside Go, even though the Apache Impala OSS documentation recommends using Hive JDBC or ODBC drivers,
the commercial Cloudera Impala includes
[dedicated drivers](https://docs.cloudera.com/documentation/other/connectors/impala-jdbc/2-6-35/Cloudera-JDBC-Connector-for-Apache-Impala-Install-Guide.pdf),
which are free to use, but not OSS. In Python, there is a first-party OSS driver for Impala and Hive -
[impyla](https://github.com/cloudera/impyla) (cool name, btw). To support both engines, that driver
includes Impala-specific [hacks](https://github.com/cloudera/impyla/blob/ab1398a/impala/hiveserver2.py#L108)

Authors of PRs in this library are encouraged to also submit them to [sqlflow.org/gohive](https://sqlflow.org/gohive),
if the code can help the Hive driver too.