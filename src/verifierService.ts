import {  TransactionRequest, TransactionReply, IVerifierServer, ErrorCode, grpc, VerifierVerifierHandshakeMessage, MerkleNodeAdvertisement, BlockAdvertisement, NeighborAdvertisement} from '@rainblock/protocol'
import { decodeTransaction, CONTRACT_CREATION } from '@rainblock/ethereum-block'
import { RlpDecode, RlpList } from 'rlp-stream';
import { BlockGenerator, AccountUpdates } from './blockGenerator';
import { hashAsBigInt, hashAsBuffer, HashType } from 'bigint-hash';
import { CachedMerklePatriciaTree, MerklePatriciaTreeNode } from '@rainblock/merkle-patricia-tree';
import { EthereumAccount, EthereumAccountFromBuffer } from './ethereumAccount';
import { toBufferBE, toBigIntBE } from 'bigint-buffer';

export class VerifierServer implements IVerifierServer {

    constructor(private logger: Logger, private blockGenerator : BlockGenerator,
        // The tree is just for decoding nodes
        private tree = new CachedMerklePatriciaTree<Buffer, EthereumAccount>()) {
    }

    async verifierVerifierHandshake(call : grpc.ServerUnaryCall<VerifierVerifierHandshakeMessage>,
        callback: grpc.sendUnaryData<VerifierVerifierHandshakeMessage>) {

        let handshakeReply = new VerifierVerifierHandshakeMessage();
        handshakeReply.setProtocolVersion(require('@rainblock/protocol/package.json').version);
        handshakeReply.setVersion(require('package.json').version);
        callback(null, handshakeReply);
    }

    async advertiseNode(call: grpc.ServerDuplexStream<MerkleNodeAdvertisement, MerkleNodeAdvertisement>) {

    }

    async advertiseBlock(call: grpc.ServerDuplexStream<BlockAdvertisement, BlockAdvertisement>) {

    }

    async advertiseNeighbor(call: grpc.ServerDuplexStream<NeighborAdvertisement, NeighborAdvertisement>) {

    }

    /** Submit a transaction from the client to the verifier. */
    async submitTransaction(call: grpc.ServerUnaryCall<TransactionRequest>, 
        callback: grpc.sendUnaryData<TransactionReply>) {
        try {
            // First grab the TX. Also hash the transaction data.
            const txBinary = call.request.getTransaction_asU8() as Buffer;
            const txRlp = RlpDecode(txBinary) as RlpList;
            const tx = await decodeTransaction(txRlp);
            const txHash = hashAsBigInt(HashType.KECCAK256, txBinary);
            this.logger.debug(`Got tx from ${call.getPeer()} from ${tx.from.toString(16)} to ${tx.to.toString(16)}`);

            // Transform the partial tree into a map we can reference
            const proofs = new Map<bigint, MerklePatriciaTreeNode<EthereumAccount>>();
            for (const witness of call.request.getAccountWitnessesList_asU8()) {
                proofs.set(hashAsBigInt(HashType.KECCAK256, Buffer.from(witness)), 
                this.tree.rlpToMerkleNode(Buffer.from(witness), v => v !== undefined && (v.length > 0) ? EthereumAccountFromBuffer(v) : v as {} as EthereumAccount));
            }

            // Queue the transaction to be added into the next block
            this.blockGenerator.addTransaction(txHash, {
                txHash,
                txRlp,
                txBinary,
                tx,
                proofs,
                fromHash: hashAsBuffer(HashType.KECCAK256, toBufferBE(tx.from, 20)),
                toHash: hashAsBuffer(HashType.KECCAK256, toBufferBE(tx.to, 20)),
                callback
            });
        } catch (e) {
            this.logger.error(`Failed to process transaction from ${call.getPeer()} - ${e instanceof Error ? e.message : e}`);
            // Some error occurred. Log it, and then return error to the client
            let r = new TransactionReply();
            r.setCode(ErrorCode.ERROR_CODE_INVALID);
            callback(null, r);
        }
    }
}