#!/usr/bin/env ts-node

import * as program from 'caporal';
import * as fs from 'fs';
import * as path from 'path';

import * as yaml from 'js-yaml';

import { VerifierServer } from './verifierService';
import { DummyStorageServer } from './dummyStorageService';
import { VerifierService, VerifierClient, TransactionRequest, TransactionReply, VerifierStorageService, grpc } from '@rainblock/protocol'
import { BlockGenerator } from './blockGenerator';
import { ConfigurationFile } from './configFile';
import { RlpDecoderTransform, RlpEncode, RlpDecode, RlpList } from 'rlp-stream/build/src/rlp-stream';
import { MerklePatriciaTree } from '@rainblock/merkle-patricia-tree/build/src';
import { getPublicAddress, encodeBlock } from '@rainblock/ethereum-block';
import { EthereumAccount } from './ethereumAccount';
import { hashAsBigInt, hashAsBuffer, HashType } from 'bigint-hash';
import { toBufferBE, toBigIntBE } from 'bigint-buffer';
import { GethStateDump } from './gethImport';
import { roots } from 'protobufjs';

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
    .action(async (a, o, l) => {
        for (let i = 0; i < 16; i++) {
            const nodeAddress = `0.0.0.0:${o[`shard${i}`]}`;
            const server = new grpc.Server();
            server.addService(VerifierStorageService, new DummyStorageServer(l));
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
        await fs.promises.writeFile(o['map'], JSON.stringify(json, null, 2), 'utf8');
        await fs.promises.writeFile(o['block'], RlpEncode(block));
    });

program.parse(process.argv);