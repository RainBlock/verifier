#!/usr/bin/env NODE_NO_WARNINGS=1 ts-node

import * as program from 'caporal';
import * as fs from 'fs';
import * as path from 'path';

import * as yaml from 'js-yaml';

import { VerifierServer } from './verifierService';
import { DummyStorageServer } from './dummyStorageService';
import { VerifierService, VerifierClient, TransactionRequest, TransactionReply, StorageNodeService, VerifierStorageService, grpc } from '@rainblock/protocol'
import { BlockGenerator } from './blockGenerator';
import { ConfigurationFile } from './configFile';
import { RlpDecoderTransform, RlpEncode, RlpDecode, RlpList } from 'rlp-stream/build/src/rlp-stream';
import { CachedMerklePatriciaTree, MerklePatriciaTree } from '@rainblock/merkle-patricia-tree/build/src';
import { EthereumTransaction, getPublicAddress, signTransaction, encodeBlock, CONTRACT_CREATION } from '@rainblock/ethereum-block';
import { EthereumAccount } from './ethereumAccount';
import { hashAsBigInt, hashAsBuffer, HashType } from 'bigint-hash';
import { toBufferBE, toBigIntBE } from 'bigint-buffer';
import { GethStateDump, ImportGethDump } from './gethImport';
import { ServiceDefinition } from 'grpc';

process.env["NODE_NO_WARNINGS"] = "1";

program.version('1').description('The rainblock verifier server')
    .command('serve', 'Start the verifier server')
    .option('--port <port-number>', 'Serve on <port-number>.', program.INTEGER, 9000)
    .option('--config <path>', 'The <path> to the configurtion file', program.STRING, path.join(__dirname, '../sample/config.yml'))
    .option('--pow <time>', 'The maximum <time> in ms the proof of work puzzle takes to solve', program.INTEGER, 12000)
    .action(async (a, o, l) => {
        let config = yaml.safeLoad(await fs.promises.readFile(o['config'], "utf8")) as ConfigurationFile;
        const server = new grpc.Server();
        const generator = new BlockGenerator(l, {
            proofOfWorkTime: o['pow'],
            config,
            configDir: path.dirname(o['config'])
        });

        server.addService(VerifierService, new VerifierServer(l, generator));
        server.bind(`0.0.0.0:${o['port']}`, grpc.ServerCredentials.createInsecure());
        server.start();

        l.info(`Serving on port ${o['port']}`);

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
    .option('--json <path>', '<path> for generated json (state file)', program.STRING)
    .action(async (a, o, l) => {
        for (let i = 0; i < 16; i++) {
            const nodeAddress = `0.0.0.0:${o[`shard${i}`]}`;
            const server = new grpc.Server();
            const storageServer = new DummyStorageServer(l, o['json']);
            server.addService(VerifierStorageService as ServiceDefinition<DummyStorageServer>, storageServer);
            server.addService(StorageNodeService as ServiceDefinition<DummyStorageServer>, storageServer);
            server.bind(nodeAddress, grpc.ServerCredentials.createInsecure());
            server.start();

            console.log(`Shard ${i} started on port ${o[`shard${i}`]}`);
        }
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
    .option('--noreply', 'Do not wait for the reply', program.BOOLEAN)
    .action(async (a, o, l) => {
        do {
            const client = new VerifierClient(o['server'], grpc.credentials.createInsecure());
            const request = new TransactionRequest();
            const data = fs.createReadStream(o['txdata']);
            const decoder = new RlpDecoderTransform();
            data.pipe(decoder);
    
            const promises = [];
            const start = process.hrtime.bigint();
            for await (const tx of decoder) {
                request.setTransaction(RlpEncode(tx));
                const promise = new Promise((resolve, reject) => {
                    client.submitTransaction(request, (err: any, reply: TransactionReply) => {
                    if (err) {
                        reject();
                    } else {
                        resolve();
                    }
                });
                });
                promises.push(promise);
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
        while (private_key < (BigInt(o['accounts']) + 1n)) {
            const address = await getPublicAddress(private_key);
            const account = new EthereumAccount(0n, BigInt(o['balance']), EthereumAccount.EMPTY_STRING_HASH, EthereumAccount.EMPTY_BUFFER_HASH);
            tree.put(hashAsBuffer(HashType.KECCAK256, toBufferBE(address, 20)), account.toRlp());
            json.accounts[address.toString(16)] = {
                balance: account.balance.toString(),
                nonce: Number(account.nonce),
                codeHash: account.codeHash.toString(16),
                storage: {},
                code: "",
                root: account.storageRoot.toString(16)
            };
            map[private_key.toString(16)] = address.toString(16); 
            private_key++;
        }

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
        await fs.promises.writeFile(o['json'], JSON.stringify(json, null, 2), 'utf8');
        await fs.promises.writeFile(o['map'], JSON.stringify(map, null, 2), 'utf8');
        await fs.promises.writeFile(o['block'], block);
    });

program.command('generate-trace', 'Generate a transaction trace file using the parameters given')
    .option('--toAccounts <number>', 'Range of to accounts to send to (0 - <number>)', program.INTEGER, undefined, true)
    .option('--fromAccountStart <number>', 'Range of from accounts to send from (<number> - end)', program.INTEGER, undefined, true)
    .option('--fromAccountEnd <number>', 'Range of from accounts to send from (start - <number>)', program.INTEGER, undefined, true)
    .option('--gasLimit <gas>', '<gas> each transaction may consume', program.INTEGER, 100000, true)
    .option('--gasPrice <price>', '<price> to pay for gas consumed', program.INTEGER, 1, true)
    .option('--value <amount>', '<amount> to transfer to the new account', program.INTEGER, 1, true)
    .option('--transactions <number>', '<number> of transactions to include in the trace', program.INTEGER, undefined, true)
    .option('--file <path>', '<path> to output file', program.STRING, undefined, true)
    .action(async (a, o, l) => {
        let transactions : RlpList[] = [];

        const nonceMap = new Map<bigint, bigint>();

        for (let i = 0; i < o['transactions']; i++) {
            const toAccountNum = Math.floor(Math.random() * o['toAccounts']) + 1; // random account between 1-toAccounts
            const fromAccountNum = Math.floor(Math.random() * (o['fromAccountsEnd'] - o['fromAccountsStart'] + 1) + o['fromAccountsEnd']); // random account between fromAccountsStart - fromAccountsEnd

            const addresses = await Promise.all([getPublicAddress(BigInt(toAccountNum)), 
                getPublicAddress(BigInt(fromAccountNum))]);

            const to = addresses[0];
            const from = addresses[1];
            
            const nonce = nonceMap.has(from) ? nonceMap.get(from)! + 1n : 0n;
            nonceMap.set(from, nonce); 
            
            let transaction : EthereumTransaction  = {
                gasLimit: BigInt(o['gasLimit']),
                to,
                data: Buffer.from([]),
                nonce: BigInt(0), //
                gasPrice: BigInt(o['gasPrice']),
                value: BigInt(o['value']),
                from: 0n // Discarded
            }

            transactions.push(signTransaction(transaction, from));
        }

        await fs.promises.writeFile(o['file'], RlpEncode(transactions));
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

program.command('proof-size', 'Calculate the sizes of proofs using varying parameters.')
    .option('--file <path>', 'Save data file to <path>', program.STRING, undefined, true)
    .action(async (a, o, l) => {
        const dummySimpleData = new EthereumAccount(0n, 5000000n, EthereumAccount.EMPTY_STRING_HASH, EthereumAccount.EMPTY_BUFFER_HASH).toRlp();
        const ADDRESS_COUNT = 64; // Represents the maximum number of calls
        // [...Array(ADDRESS_COUNT + 1).keys()].slice(1)
        // returns an array [1...ADDRESS_COUNT]
        const addresses = await Promise.all([...Array(ADDRESS_COUNT + 1).keys()].slice(1).map(k => getPublicAddress(BigInt(k))));
        const hashes = addresses.map(m => hashAsBuffer(HashType.KECCAK256, toBufferBE(m, 20)));
        const data : { [ count : number] : {} } = {};

        for (let accounts = 100000; accounts <= 10_000_000; accounts *= 10) {
            const accountData : any = {};
            accountData.pruningLevel = {};
            const tree = new MerklePatriciaTree();
            for (let accountKey = 1; accountKey < accounts + 1; accountKey++) {
                const address = await getPublicAddress(BigInt(accountKey));               
                tree.put(hashAsBuffer(HashType.KECCAK256, toBufferBE(address, 20)), dummySimpleData);
            }

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
                for (let totalAccounts = 2; totalAccounts < ADDRESS_COUNT + 1; totalAccounts++) {
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