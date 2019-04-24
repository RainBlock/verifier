import {  IVerifierStorageServer, 
    IStorageNodeServer,
    UpdateMsg, google_protobuf_empty_pb, grpc, CodeRequest, CodeReply, AccountRequest, AccountReply, StorageRequest, StorageReply, BlockHashRequest, BlockHashReply, RPCWitness} from '@rainblock/protocol'
import { MerklePatriciaTree } from '@rainblock/merkle-patricia-tree/build/src';
import { GethStateDump, ImportGethDump } from './gethImport';
import { EthereumAccount } from './ethereumAccount';
import { hashAsBigInt, hashAsBuffer, HashType, KeccakHasher } from 'bigint-hash';
import { toBufferBE, toBigIntBE } from 'bigint-buffer';

import * as path from 'path';
import * as fs from 'fs';


export class DummyStorageServer implements IVerifierStorageServer, IStorageNodeServer {

    tree = new MerklePatriciaTree<Buffer, EthereumAccount>( {
        keyConverter: k => k,
        valueConverter: v => v.toRlp(),
        putCanDelete: false
    });

    constructor(private logger : Logger, shardNumber : number, genesisData?: string, compressed = false, public compactionLevel = 0) {

        if (genesisData !== undefined) {
            ImportGethDump(genesisData, this.tree, new Map<bigint, Buffer>(), compressed, shardNumber)
                .then(() => {
                    this.logger.info(`Initialized state to stateRoot ${this.tree.rootHash.toString(16)}`);
                });
        }
    }

    async getCodeInfo(call: grpc.ServerUnaryCall<CodeRequest>, 
        callback: grpc.sendUnaryData<CodeReply>) {
            this.logger.debug(`Got code info message from ${call.getPeer()}`);
            callback(null, new CodeReply());
        }

    async getAccount(call: grpc.ServerUnaryCall<AccountRequest>,
        callback: grpc.sendUnaryData<AccountReply>) {
            this.logger.debug(`Got account message from ${call.getPeer()}`);
            let accountBuffer = call.request.getAddress_asU8();
            let account = this.tree.get(hashAsBuffer(HashType.KECCAK256, Buffer.from(accountBuffer)));
            let reply = new AccountReply();
            reply.setExists(account.value === null);
            if (account.value !== null) {
                let rpcWitness = new RPCWitness();
                rpcWitness.setValue(account.value.toRlp());
                rpcWitness.setProofListList(
                    account.proof.length === 1 || this.compactionLevel > account.proof.length ? 
                    account.proof.map(n => n.getRlpNodeEncoding({
                        keyConverter: k => k as Buffer,
                        valueConverter: v => v.toRlp() ,
                    putCanDelete: false
                })) :
                account.proof.slice(this.compactionLevel).map(n => n.getRlpNodeEncoding({
                    keyConverter: k => k as Buffer,
                    valueConverter: v => v.toRlp() ,
                putCanDelete: false
            }))
                );
            }
            callback(null, reply);
        }

    async getStorage(call: grpc.ServerUnaryCall<StorageRequest>,
        callback: grpc.sendUnaryData<StorageReply>) {
            this.logger.debug(`Got storage message from ${call.getPeer()}`);
            callback(null, new StorageReply());
        }

    async getBlockHash(call: grpc.ServerUnaryCall<BlockHashRequest>, 
        callback: grpc.sendUnaryData<BlockHashReply>) {
            this.logger.debug(`Got block hash message from ${call.getPeer()}`);
            callback(null, new BlockHashReply());
        }

    async update(call: grpc.ServerUnaryCall<UpdateMsg>, 
        callback: grpc.sendUnaryData<google_protobuf_empty_pb.Empty>) {
        this.logger.debug(`Got update message from ${call.getPeer()}`);
        callback(null, new google_protobuf_empty_pb.Empty());
    }
}