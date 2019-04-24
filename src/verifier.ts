#!/usr/bin/env NODE_NO_WARNINGS=1 ts-node

import * as program from 'caporal';
import * as fs from 'fs';
import * as path from 'path';

import * as yaml from 'js-yaml';

import { VerifierServer } from './verifierService';
import { DummyStorageServer } from './dummyStorageService';
import { IVerifierServer, VerifierService, VerifierClient, TransactionRequest, TransactionReply, StorageNodeService, VerifierStorageService, grpc } from '@rainblock/protocol'
import { BlockGenerator } from './blockGenerator';
import { ConfigurationFile } from './configFile';
import { RlpDecoderTransform, RlpEncode, RlpDecode, RlpList } from 'rlp-stream/build/src/rlp-stream';
import { CachedMerklePatriciaTree, MerklePatriciaTree } from '@rainblock/merkle-patricia-tree/build/src';
import { EthereumTransaction, getPublicAddress, signTransaction, encodeBlock, CONTRACT_CREATION, decodeTransaction } from '@rainblock/ethereum-block';
import { EthereumAccount } from './ethereumAccount';
import { hashAsBigInt, hashAsBuffer, HashType } from 'bigint-hash';
import { toBufferBE, toBigIntBE } from 'bigint-buffer';
import { GethStateDump, ImportGethDump } from './gethImport';
import { ServiceDefinition } from 'grpc';
import { NetworkLearner } from './networkLearner';
import * as progress from 'cli-progress';
import * as colors from 'colors';

import {chain} from 'stream-chain';
import {parser} from 'stream-json';
import {pick} from 'stream-json/filters/Pick';
import {streamObject} from 'stream-json/streamers/StreamObject';

import * as zlib from 'zlib';


process.env["NODE_NO_WARNINGS"] = "1";

program.version('1').description('The rainblock verifier server')
    .command('serve', 'Start the verifier server')
    .option('--port <port-number>', 'Serve on <port-number>.', program.INTEGER, 9000)
    .option('--config <path>', 'The <path> to the configurtion file', program.STRING, path.join(__dirname, '../sample/config.yml'))
    .option('--beneficiary <address>', 'The <address> of the beneficiary. If set, overrides any beneficary set in the config.', program.STRING)
    .option('--wait', 'Wait to connect to all verifiers before generating blocks', program.BOOLEAN)
    .action(async (a, o, l) => {
        let config = yaml.safeLoad(await fs.promises.readFile(o['config'], "utf8")) as ConfigurationFile;

        if (o['beneficiary']) {
            config.beneficiary = o['beneficiary'];
        }

        const server = new grpc.Server();

        const learner = new NetworkLearner(l, config);
        const generator = new BlockGenerator(l, {
            config,
            configDir: path.dirname(o['config'])
        }, learner);

        // First, initialize the block generator state
        await generator.initialize();

        // Then start the verifier service
        server.addService(VerifierService, new VerifierServer(l, config, generator));
        server.bind(`0.0.0.0:${o['port']}`, grpc.ServerCredentials.createInsecure());
        server.start();

        l.info(`Serving on port ${o['port']} as beneficiary ${config.beneficiary}`);
        learner.startLearning();



        // If we need to wait for all neighbors
        if (o['wait']) {
            await learner.waitForAllNeighbors();
        }

        try {
            await generator.generate();
        } catch (e) {
            l.error(`Terminating due to error`);
            console.log(e);
            process.exit(1);
        }
    });

program.command('test-storage', 'Start up a test storage node')
    .option('--shard0 <port-number>', 'Serve shard 0 on <port-number>.', program.INTEGER, 9100)
    .option('--shard1 <port-number>', 'Serve shard 1 on <port-number>.', program.INTEGER, 9101)
    .option('--shard2 <port-number>', 'Serve shard 2 on <port-number>.', program.INTEGER, 9102)
    .option('--shard3 <port-number>', 'Serve shard 3 on <port-number>.', program.INTEGER, 9103)
    .option('--shard4 <port-number>', 'Serve shard 4 on <port-number>.', program.INTEGER, 9104)
    .option('--shard5 <port-number>', 'Serve shard 5 on <port-number>.', program.INTEGER, 9105)
    .option('--shard6 <port-number>', 'Serve shard 6 on <port-number>.', program.INTEGER, 9106)
    .option('--shard7 <port-number>', 'Serve shard 7 on <port-number>.', program.INTEGER, 9107)
    .option('--shard8 <port-number>', 'Serve shard 8 on <port-number>.', program.INTEGER, 9108)
    .option('--shard9 <port-number>', 'Serve shard 9 on <port-number>.', program.INTEGER, 9109)
    .option('--shard10 <port-number>', 'Serve shard 10 on <port-number>.', program.INTEGER, 9110)
    .option('--shard11 <port-number>', 'Serve shard 11 on <port-number>.', program.INTEGER, 9111)
    .option('--shard12 <port-number>', 'Serve shard 12 on <port-number>.', program.INTEGER, 9112)
    .option('--shard13 <port-number>', 'Serve shard 13 on <port-number>.', program.INTEGER, 9113)
    .option('--shard14 <port-number>', 'Serve shard 14 on <port-number>.', program.INTEGER, 9114)
    .option('--shard15 <port-number>', 'Serve shard 15 on <port-number>.', program.INTEGER, 9115)
    .option('--compactionLevel <level>', '<level> of compaction', program.INTEGER, 0)
    .option('--compressed', 'if JSON is compressed', program.BOOLEAN, false)
    .option('--json <path>', '<path> for generated json (state file)', program.STRING)
    .action(async (a, o, l) => {
        for (let i = 0; i < 16; i++) {
            const nodeAddress = `0.0.0.0:${o[`shard${i}`]}`;
            const server = new grpc.Server();
            const storageServer = new DummyStorageServer(l, i , o['json'], o['compressed'], o['compactionLevel']);
            server.addService(VerifierStorageService as ServiceDefinition<DummyStorageServer>, storageServer);
            server.addService(StorageNodeService as ServiceDefinition<DummyStorageServer>, storageServer);
            server.bind(nodeAddress, grpc.ServerCredentials.createInsecure());
            server.start();

            console.log(`Shard ${i} started on port ${o[`shard${i}`]}`);
        }
    });


program.command('test-storage-single', 'Start up a single test storage node')
.option('--port <port-number>', 'Serve on <port-number>.', program.INTEGER, 9100)
.option('--compactionLevel <level>', '<level> of compaction', program.INTEGER, 0)
.option('--compressed', 'if JSON is compressed', program.BOOLEAN, false)
.option('--shard <number>', 'shard number', program.INTEGER, 0)
.option('--json <path>', '<path> for generated json (state file)', program.STRING)
.action(async (a, o, l) => {
        const nodeAddress = `0.0.0.0:${o['port']}`;
        const server = new grpc.Server();
        const storageServer = new DummyStorageServer(l,  o['shard'], o['json'], o['compressed'], o['compactionLevel']);
        server.addService(VerifierStorageService as ServiceDefinition<DummyStorageServer>, storageServer);
        server.addService(StorageNodeService as ServiceDefinition<DummyStorageServer>, storageServer);
        server.bind(nodeAddress, grpc.ServerCredentials.createInsecure());
        server.start();

        console.log(`Started on port ${o['port']}`);
});


program.command('test-transaction', 'Send a test transaction')
    .option('--server <server>', 'Send transaction to <server>', program.STRING, 'localhost:9000')
    .option('--txdata <tx-path>', 'Path to file with transaction data', program.STRING, undefined, true)
    .action(async (a, o, l) => {
        const client = new VerifierClient(o['server'], grpc.credentials.createInsecure());
        const request = new TransactionRequest();
        const data = await fs.promises.readFile(o['txdata']);
        request.setTransaction(data);
        client.submitTransaction(request, (err: any, reply: TransactionReply) => {
            if (err) {
                console.error(err);
            } else {
                console.log(reply.getCode());
            }
        });
    });

program.command('test-transaction-list', 'Send a list of test transactions')
    .option('--server <server>', 'Send transaction to <server>', program.STRING, 'localhost:9000')
    .option('--txdata <tx-path>', 'Path to file with transaction data list', program.STRING, undefined, true)
    .option('--repeat', 'Whether or not to keep sending over and over again', program.BOOLEAN)
    .option('--concurrency <level>', 'Number of concurrent requests to <level> ', program.INTEGER, 10000)
    .option('--noreply', 'Do not wait for the reply', program.BOOLEAN)
    .action(async (a, o, l) => {
        do {
            const client = new VerifierClient(o['server'], grpc.credentials.createInsecure());
            const request = new TransactionRequest();
            const data = fs.createReadStream(o['txdata']);
            const decoder = new RlpDecoderTransform();
            data.pipe(decoder);
    
            let promises = [];
            const start = process.hrtime.bigint();
            let i = 0;
            for await (const tx of decoder) {
                request.setTransaction(RlpEncode(tx));
                const promise = new Promise((resolve, reject) => {
                    const l = client.submitTransaction(request, (err: any, reply: TransactionReply) => {
                    if (err) {
                        reject();
                    } else {
                        resolve();
                    }
                });
                });
                promises.push(promise);
                if (!o['noreply'] && promises.length > o['concurrency']) {
                    await Promise.all(promises);
                    promises = [];
                }
            }

            if (!o['noreply']) {
                await Promise.all(promises);
            }

            const end = process.hrtime.bigint();
            const total = end - start;
            l.info(`Processed ${promises.length} txes in ${total} ns (${total/BigInt(promises.length)} ns/op)`);
        } while (o['repeat']);

    });

program.command('generate-genesis', 'Generate a genesis file and block with test accounts')
    .option('--json <path>', '<path> for generated json (state file)', program.STRING, undefined, true)
    .option('--block <path>', '<path> for generated block file', program.STRING, undefined, true)
    .option('--map <path>', '<path> for map of privkey to account', program.STRING, undefined, true)
    .option('--accounts <number>', '<number> of accounts to generate', program.INTEGER, 100000, true)
    .option('--balance <amount>', '<amount> to seed each account balance with', program.INTEGER, 100000, true)
    .action(async (a, o, l) => {
        let private_key = 1n;
        const tree = new MerklePatriciaTree();
        const json : GethStateDump = {
            root: "",
            accounts: {}
        }
        const map : { [private_key : string] : string} = {};
        l.info('Generating accounts');
        
        // Account is constant
        const account = new EthereumAccount(0n, BigInt(o['balance']), EthereumAccount.EMPTY_STRING_HASH, EthereumAccount.EMPTY_BUFFER_HASH);
        const jsonAccount = {
            balance: account.balance.toString(),
            nonce: Number(account.nonce),
            codeHash: account.codeHash.toString(16),
            storage: {},
            code: "",
            root: account.storageRoot.toString(16)
        };


        let bar = new progress.Bar({
            format: 'Generating Public Key |' + colors.cyan('{bar}') + '| {percentage}% | Key: {value}/{total} | elapsed: {duration_formatted}',
            etaBuffer : 5
        }, progress.Presets.shades_classic);

        bar.start(o['accounts'], 0);

        while (private_key < (BigInt(o['accounts']) + 1n)) {
            const address = await getPublicAddress(private_key);
            json.accounts[address.toString(16)] = jsonAccount;
            map[private_key.toString(16)] = address.toString(16); 
            bar.update(Number(private_key));
            private_key++;
        }

        bar.stop();

        l.info('Done generating accounts, generating tree');
        bar = new progress.Bar({
            format: 'Adding to tree |' + colors.cyan('{bar}') + '| {percentage}% | Key: {value}/{total} | elapsed: {duration_formatted}',
            etaBuffer : 5
        }, progress.Presets.shades_classic);

        bar.start(o['accounts'], 0);
        const accountRlp = account.toRlp();
        let i = 0;
        for (const [key, address] of Object.entries(map)) {
            tree.put(hashAsBuffer(HashType.KECCAK256, toBufferBE(BigInt(`0x${address.padStart(20, '0')}`), 20)), accountRlp);
            bar.update(i);
            i++;
        }
        bar.stop();
        l.info('Done generating tree. Generating root hash.');

        json.root = tree.rootHash.toString(16);
        const block = encodeBlock( {
            parentHash: 0n,
            uncleHash: 0n,
            beneficiary: 0n,
            stateRoot: tree.rootHash,
            transactionsRoot: EthereumAccount.EMPTY_BUFFER_HASH,
            receiptsRoot: EthereumAccount.EMPTY_BUFFER_HASH, 
            logsBloom: Buffer.from([]), 
            difficulty: 0n,
            gasLimit: 0n,
            gasUsed: 0n,
            timestamp: BigInt(new Date().valueOf()),
            extraData: Buffer.from("rainblock-genesis", "ascii"),
            mixHash: 0n, // TODO: generate a valid mixHash
            nonce: 0n, // TODO: pick a valid nonce
            blockNumber: 0n
        }, [], []);

        l.info(`Writing output files.`);
        await fs.promises.writeFile(o['block'], block);
        await fs.promises.writeFile(o['json'], JSON.stringify(json, null, 2), 'utf8');
        await fs.promises.writeFile(o['map'], JSON.stringify(map, null, 2), 'utf8')
    });

program.command('generate-trace', 'Generate a transaction trace file using the parameters given')
    .option('--toAccounts <number>', 'Range of to accounts to send to (0 - <number>)', program.INTEGER, undefined, true)
    .option('--fromAccountsStart <number>', 'Range of from accounts to send from (<number> - end)', program.INTEGER, undefined, true)
    .option('--fromAccountsEnd <number>', 'Range of from accounts to send from (start - <number>)', program.INTEGER, undefined, true)
    .option('--gasLimit <gas>', '<gas> each transaction may consume', program.INTEGER, 100000, true)
    .option('--gasPrice <price>', '<price> to pay for gas consumed', program.INTEGER, 1, true)
    .option('--value <amount>', '<amount> to transfer to the new account', program.INTEGER, 1, true)
    .option('--chain <id>', '<id> of the chain (0 for pre-EIP-155 semantics, 1 for mainnet)', program.INTEGER, 0)
    .option('--transactions <number>', '<number> of transactions to include in the trace', program.INTEGER, undefined, true)
    .option('--file <path>', '<path> to output file', program.STRING, undefined, true)
    .option('--contract <contract>', 'A contract from ["omg", "bittrex", "etherdelta"] for the transaction to call', program.STRING, undefined, false)
    .option('--contractAddress <contractAddress>', 'Simulated address of the selected contract', program.STRING, undefined, false)
    .action(async (a, o, l) => {
        

        const nonceMap = new Map<bigint, bigint>();
        const ws = fs.createWriteStream(o['file']);

        for (let i = 0; i < o['transactions']; i++) {
            const toAccountNum = BigInt(Math.floor(Math.random() * o['toAccounts']) + 1); // random account between 1-toAccounts
            const fromAccountNum = BigInt(Math.floor(Math.random() * (o['fromAccountsEnd'] - o['fromAccountsStart'] + 1) + o['fromAccountsStart'])); // random account between fromAccountsStart - fromAccountsEnd
            
            var to = await getPublicAddress(toAccountNum);
            var value = BigInt(o['value']);
            
            const nonce = nonceMap.has(fromAccountNum) ? nonceMap.get(fromAccountNum)! + 1n : 0n;
            nonceMap.set(fromAccountNum, nonce); 
        
            var txnData = Buffer.from([]);
            if (o['contract']) {
                switch(o['contract']) {
                    case "omg":
                        var addr1 = to;
                        value = 0n; // Txn value for this contract must be 0

                        const contractvalue = BigInt(Math.floor(Math.random() * 10000 + 1));
                        var valueStr = contractvalue.toString(16);
                        // Pad valueStr with zeroes
                        while (valueStr.length < 64) {
                            valueStr = '0' + valueStr;
                        }
                        var addr1Str = addr1.toString(16);
                        // Pad with zeroes
                        addr1Str = addr1Str.padStart(64, '0');

                        if (o['contractAddress'])
                            to = BigInt(o['contractAddress']);
                        else {
                            // This is the Ethereum address of the OMGToken contract
                            to = 0xd26114cd6EE289AccF82350c8d8487fedB8A0C07n;
                        }
                        // This is how to construct the ABI call for the `transfer` function in
                        // the OMG contract, which consists of a target addr and a value
                        txnData = Buffer.from('a9059cbb' + addr1Str + valueStr, 'hex');
                        console.log(txnData.toString('hex'));
                        break;
                    case "bittrex":
                        value = BigInt(Math.floor(Math.random() * 10000 + 1));
                        var addr1 = to;
                        const anotherAddr = BigInt(Math.floor(Math.random() * (o['fromAccountsEnd'] - o['fromAccountsStart'] + 1) + o['fromAccountsStart']));
                        var addr2 = await getPublicAddress(anotherAddr);

                        var addr1Str = addr1.toString(16);
                        // Pad with zeroes
                        addr1Str = addr1Str.padStart(64, '0');
                        var addr2Str = addr2.toString(16);
                        // Pad with zeroes
                        addr2Str = addr2Str.padStart(64, '0');

                        if (o['contractAddress'])
                            to = BigInt(o['contractAddress']);
                        else {
                            // This is the Ethereum address of the BittrexToken contract
                            to = 0xE94b04a0FeD112f3664e45adb2B8915693dD5FF3n;
                        }
                        // This is how to construct the ABI call for the `split` function in
                        // the Bittrex contract, which consists of 2 addr parameters
                        txnData = Buffer.from('0f2c9329' + addr1Str + addr2Str, 'hex');
                        console.log(txnData.toString('hex'));
                        break;
                    case "etherdelta":
                        console.log("Oops, etherdelta contract not implemented yet");
                        break;
                    default:
                        console.log("Provided invalid contract name");
                        return;
                }
            }

            let transaction : EthereumTransaction  = {
                gasLimit: BigInt(o['gasLimit']),
                to,
                data: txnData,
                nonce,
                gasPrice: BigInt(o['gasPrice']),
                value: value,
                from: 0n // Discarded
            }
            
            const signedTx = signTransaction(transaction, fromAccountNum, o['chain']);
            const rlp = RlpEncode(signedTx);

            ws.write(rlp);
        }

        ws.close();
    });

program.command('submit-tx', 'Submit a transaction using parameters given.')
    .option('--server <server>', 'Send transaction to <server>', program.STRING, 'localhost:9000')
    .option('--file <path>', 'Save transaction as binary to <path> instead of sending to server', program.STRING, undefined)
    .option('--key <private-key>', '<private-key>, in hex to use', program.STRING, undefined, true)
    .option('--to <account>', '<account>, in hex to send to', program.STRING, undefined, true)
    .option('--nonce <number>', '<number> of transactions from this account', program.INTEGER, 0)
    .option('--gas <amount>', '<amount> of gas to start with', program.INTEGER, 21000)
    .option('--gasPrice <wei>', '<wei> to pay for each unit of gas used', program.INTEGER, 1)
    .option('--value <wei>', '<wei> to send with the transaction', program.INTEGER, 1)
    .option('--chain <id>', '<id> of the chain (0 for pre-EIP-155 semantics, 1 for mainnet)', program.INTEGER, 0)
    .option('--data <data>', '<data> in hex to send with the transaction', program.STRING, "")
    .option('--proof', 'generate proofs (for simple txes)',  program.BOOLEAN, false)
    .option('--proofState <path>', '<path> to json state to generate proof from', program.STRING, "sample/simple.json")
    .option('--proofTrim <depth>', 'trim any proof level above <depth>',  program.INTEGER, 0)
    .action(async (a, o, l) => {
        // Pad the input key and the to account
        const keyPadded = (o['key'] as string).padStart(64, '0');
        const toPadded = (o['to'] as string).padStart(40, '0');
        const transaction : EthereumTransaction = {
            nonce: BigInt(o['nonce']),
            gasLimit: BigInt(o['gas']),
            gasPrice: BigInt(o['gasPrice']),
            value: BigInt(o['value']),
            to: o['to'] ===  "-1" ? CONTRACT_CREATION : toBigIntBE(Buffer.from(toPadded, 'hex')),
            data: Buffer.from(o["data"], 'hex'),
            from: 0n
        };
        // Sign the transaction and generate the binary
        const signedTransaction = signTransaction(transaction, toBigIntBE(Buffer.from(keyPadded, 'hex')), o['chain']);
        const txBinary = RlpEncode(signedTransaction);
        let proof = [];

        // Generate the proof (for simple tx only)
        if (o['proof']) {
            const tree = new MerklePatriciaTree<Buffer, EthereumAccount>();
            await ImportGethDump(o['proofState'], tree, new Map<bigint, Buffer>());

            const fromProof = tree.get(hashAsBuffer(HashType.KECCAK256, toBufferBE(await getPublicAddress(BigInt(`0x${keyPadded}`)), 20)));
            const toProof = tree.get(hashAsBuffer(HashType.KECCAK256, Buffer.from(toPadded, 'hex')));

            proof.push(...fromProof.proof.slice(o['proofTrim']));
            proof.push(...toProof.proof.slice(o['proofTrim']));
            l.debug(`Added ${proof.length} nodes to proof`);
        }

        // Save to file or send to remote
        if (o['file']) {
            await fs.promises.writeFile(o['file'], txBinary);
        } else {
            const client = new VerifierClient(o['server'], grpc.credentials.createInsecure());
            const request = new TransactionRequest();
            request.setTransaction(txBinary);
            if (o['proof']) {
                const proofs = proof.map(p => p.getRlpNodeEncoding({
                    keyConverter: k => k as Buffer,
                    valueConverter: v => v.toRlp(),
                    putCanDelete: false}));
                const fullBytes = proofs.reduce((p, c, i) => p + c.length, 0);
                l.debug(`Proofs total size: ${fullBytes}`);
                const hashes : bigint[] = [];
                const reduced = [];
                for (const proof of proofs) {
                    const hash = hashAsBigInt(HashType.KECCAK256, proof);
                    if (hashes.indexOf(hash) === -1) {
                        hashes.push(hash);
                        reduced.push(proof);
                    }
                }
                const reducedBytes = reduced.reduce((p, c, i) => p + c.length, 0);
                l.debug(`Overlap reduction - removed ${proofs.length - reduced.length} proofs, reduced ${fullBytes - reducedBytes} bytes to ${reducedBytes}`);
                request.setAccountWitnessesList(proofs);
            }
            await new Promise((resolve, reject) => {
                client.submitTransaction(request, (err: any, reply: TransactionReply) => {
                if (err) {
                    reject();
                } else {
                    resolve();
                }
            });
            });
            client.close();
        }
    });

program.command('split-state', 'Split a JSON file into multiple states per shard')
    .option('--file <path>', 'compressed state file to split into multiple files', program.STRING)
    .action(async (a,o,l) => {
        const pipeline = chain([
            fs.createReadStream(o['file']),
            zlib.createGunzip(),
            parser(),
            pick({filter: 'accounts'}),
            streamObject(),
          ]);
        let i = 0;
        const shards : GethStateDump[] = [];
        for (let i = 0 ; i < 16; i++) {
            shards[i] = {
                root: "",
                accounts : {}
            }
        }
        for await (const data of pipeline) {
            const account = data.value;
            const id = data.key;

            const hashed = hashAsBuffer(HashType.KECCAK256, toBufferBE(BigInt(`0x${id}`), 20));
            const topNibble = (hashed[0] & 0xF0) >> 4;
            shards[topNibble].accounts[id] = {
                balance: account.balance,
                nonce: account.nonce,
                codeHash: account.codeHash,
                root: account.root,
                code: account.code,
                storage: account.storage
            }
            if (i % 10000 === 0) {
                console.log(`Imported ${i} accounts`);
            }
            i++;
        }
        for (let i = 0 ; i < 16; i++) {
            await fs.promises.writeFile(`shard.${i}.json`, JSON.stringify(shards[i]));
            console.log(`Wrote shard ${i}`);
        }
    })


program.command('proof-size', 'Calculate the sizes of proofs using varying parameters.')
    .option('--multiply', 'Multiply by 10 instead of increment', program.BOOLEAN, false)
    .option('--fastgen', 'Generate mock accounts instead of performing secp256k1 brute force', program.BOOLEAN, false)
    .option('--addressStart <number>', 'Number of addresses to start at', program.INTEGER, 2)
    .option('--addressCount <count>', 'Number of addresses total', program.INTEGER, 64)
    .option('--file <path>', 'Save data file to <path>', program.STRING, undefined, true)
    .action(async (a, o, l) => {
        const dummySimpleData = new EthereumAccount(0n, 5000000n, EthereumAccount.EMPTY_STRING_HASH, EthereumAccount.EMPTY_BUFFER_HASH).toRlp();
        // [...Array(ADDRESS_COUNT + 1).keys()].slice(1)
        // returns an array [1...ADDRESS_COUNT]
        const addresses = await Promise.all([...Array(o['addressCount'] + 1).keys()].slice(1).map(k => getPublicAddress(BigInt(k))));
        const hashes = addresses.map(m => hashAsBuffer(HashType.KECCAK256, toBufferBE(m, 20)));
        const data : { [ count : number] : {} } = {};

        for (let accounts = 100000; accounts <= 10_000_000; accounts *= 10) {
            l.info(`Processing ${accounts} accounts`);
            const accountData : any = {};
            accountData.pruningLevel = {};
            const tree = new MerklePatriciaTree();
            for (let accountKey = 1; accountKey < accounts + 1; accountKey++) {
                const address = o['fastgen'] ? hashAsBigInt(HashType.SHA1, toBufferBE(BigInt(accountKey), 20)) : await getPublicAddress(BigInt(accountKey));               
                tree.put(hashAsBuffer(HashType.KECCAK256, toBufferBE(address, 20)), dummySimpleData);
            }
            l.info(`Generated world state, testing witness sizes`);

            const witness = hashes.map(m => tree.get(m));
            
            l.debug(`${accounts} depths: ${witness.map(m => m.proof.length)}`);

            accountData.depths = witness.map(m => m.proof.length);

            const converted = witness.map(m => m.proof) 
                .map(ps => ps.map(p => p.getRlpNodeEncoding({
                    keyConverter: k => k as Buffer,
                    valueConverter: v => v,
                    putCanDelete: false})));
                

            // try different pruning depths starting at 10 to 0
            for (let depth = 10; depth >= 0; depth--) {
                const depthData : any = {};
                
                const sliced = converted.map(m => m.length > depth ? m.slice(depth) : [m[m.length - 1]]) // preserve the last proof

                // for 2-ADDRESS_COUNT...
                for (let totalAccounts = o['addressStart']; totalAccounts < o['addressCount'] + 1; o['multiply'] ? totalAccounts *= 10 : totalAccounts++) {
                    const callData : any = {};

                    const proofs : Buffer[] = [];
                    sliced.slice(0, totalAccounts)
                        .forEach(s => proofs.push(...s));

                    const unprunedProofs : Buffer[] = [];
                    converted.slice(0, totalAccounts)
                        .forEach(s => unprunedProofs.push(...s));
                    const unprunedBytes = unprunedProofs.reduce((p, c, i) => p + c.length, 0);
                

                    const fullBytes = proofs.reduce((p, c, i) => p + c.length, 0);

                    callData.unprunedBytes = unprunedBytes;
                    callData.prunedBytes = fullBytes;

                    l.debug(`${accounts} ${depth} ${totalAccounts} Proofs total size: pruned ${fullBytes} vs unpruned ${unprunedBytes} (${((1 - (fullBytes/unprunedBytes)) * 100).toFixed(2)}%)`);
                    const hashes : bigint[] = [];
                    const reduced = [];
                    for (const proof of proofs) {
                        const hash = hashAsBigInt(HashType.KECCAK256, proof);
                        if (hashes.indexOf(hash) === -1) {
                            hashes.push(hash);
                            reduced.push(proof);
                        }
                    }

                    const reducedBytes = reduced.reduce((p, c, i) => p + c.length, 0);
                    callData.reducedBytes = reducedBytes;
                    depthData[totalAccounts] = callData;
                    l.debug(`${accounts} ${depth} ${totalAccounts} Overlap reduction - removed ${proofs.length - reduced.length} proofs, reduced ${fullBytes - reducedBytes} bytes to ${reducedBytes} (${((1 - (reducedBytes/fullBytes)) * 100).toFixed(2)}% vs pruned, ${((1 - (reducedBytes/unprunedBytes)) * 100).toFixed(2)}% vs unpruned)`);
                }
                accountData.pruningLevel[depth] = depthData;
            }

            data[accounts] = accountData;
        }

        await fs.promises.writeFile(o['file'], JSON.stringify(data, null, 2), 'utf8');
    });

program.parse(process.argv);
