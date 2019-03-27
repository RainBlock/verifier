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