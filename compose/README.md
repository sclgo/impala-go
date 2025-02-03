# Local Impala demo

`compose.yml` and the rest of the files in this folder define a local Apache Impala installation
and an end-to-end demo of querying large open data using Golang.

To start the demo, run:

```bash
docker compose up --wait
```

then navigate to <http://localhost:21888/lab/tree/host/demo.ipynb> . Password is `foobar`.
