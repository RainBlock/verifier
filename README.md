# Rainblock Verifier

The Rainblock verifier executes and verifies Ethereum blocks and submits the result to
the storage engine. Clients submit transactions to the verifier to be included in the
chain.

# Running the verifier

The verifier requires a configuration file. A sample file can be found in `sample/config.yml`.
Documentation on the various configuration options can be found in `src/configFile.ts`.

You can run the verifier if you have installed this package globally:
```
$ npm install -g
```

This should install the verifier on your system, which should install the verifier command.
If you run the command without arguments, you should get basic help.

Running:
```
$ verifier serve
```

Should start the verifier as a service.

A Dockerfile is included, which serves the verifier using the sample files on port 9000. To build it, run:
```
$ docker build --rm -f "Dockerfile" -t rainblock-verifier:latest .
```

From this directory. Then run
```
$ docker run rainblock-verifier:latest verifier serve
```

# Running a simple workload

The verifier comes with a simple test workload. The sample/txes.bin file contains a list of the first
10K non-contract transactions (without proofs) in the Ethereum mainnet, and the genesis.bin/genesis.json
files will initialize the verifier to the genesis state.

You can run a test verifier client by running
```
$ verifier test-transaction-list --txdata=sample/txes.bin
```

Against a working verifier server.