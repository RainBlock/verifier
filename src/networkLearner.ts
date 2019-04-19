import { ConfigurationFile } from "./configFile";
import { VerifierClient, grpc, VerifierVerifierHandshakeMessage, MerkleNodeAdvertisement, BlockAdvertisement, NeighborAdvertisement } from "@rainblock/protocol";
import { waitForClient, waitForRpc, delay } from "./grpcUtil";
import { toBufferBE, toBigIntBE } from 'bigint-buffer';
import { Duplex } from "stream";
import { EthereumBlock, encodeBlock } from "@rainblock/ethereum-block/dist/ethereum-block";
import { RlpEncode } from "rlp-stream/build/src/rlp-stream";
import { configure } from "protobufjs";

export interface NeighborData {
    address : string;
    beneficiary : bigint;
    nodeStream : grpc.ClientDuplexStream<MerkleNodeAdvertisement, MerkleNodeAdvertisement>;
    blockStream : grpc.ClientDuplexStream<BlockAdvertisement, BlockAdvertisement>;
    neighborStream: grpc.ClientDuplexStream<NeighborAdvertisement, NeighborAdvertisement>;
}

// The NetworkLearner manages connections with and learns about updates from other verifiers in the network.
export class NetworkLearner {

    connectedSet = new Set<string>();
    neighbors = new Map<bigint, NeighborData>();

    running : boolean  = false;

    // For now, we'll just send updates to each hop
    constructor(public log : Logger, public config : ConfigurationFile) {
        
    }

    /** Wait for all neighbors to connect, waiting at the RPC rescan interval */
    async waitForAllNeighbors() {
        while (this.config.verifiers && this.connectedSet.size != this.config.verifiers.length) {
            this.log.info(`Waiting to connect to ${this.config.verifiers.length} verifiers, connected to ${this.connectedSet.size}`);
            await delay(this.config.rpc.rescanInterval);
        }
        this.log.info(`Connected to ${this.connectedSet.size} verifiers`);
    }

    /** Advertise a new RLP-encoded block to all neighbors
     * 
     * @param blockAsBuffer The RLP-encoded block
     */
    async advertiseBlockToNeighbors(blockAsBuffer : Buffer) {
        const advertisement = new BlockAdvertisement();
        advertisement.setBlock(blockAsBuffer);
        for (const [beneficiary, neighbor] of this.neighbors.entries()) {
            neighbor.blockStream.write(advertisement);
            this.log.debug(`Advertised block to neighbor ${beneficiary.toString(16)} at ${neighbor.address}`);
        }
    }

    /** Advertise a set of RLP-encoded nodes to all neighbors
     * 
     * @param nodesAsBuffers The RLP-encoded nodes
     */
    async advertiseNodesToNeighbors(nodesAsBuffers : Buffer[]) {
        const advertisement = new MerkleNodeAdvertisement();
        advertisement.setNodeList(nodesAsBuffers);
        for (const [beneficiary, neighbor] of this.neighbors.entries()) {
            neighbor.nodeStream.write(advertisement);
            this.log.debug(`Advertised nodes to neighbor ${beneficiary.toString(16)} at ${neighbor.address}`);
        }
    }

    /** Start learning about new neighbors */
    async startLearning() {
        this.running = true;
        while (this.running) {
            for (const address of this.config.verifiers) {
                if (!this.connectedSet.has(address)) {
                    try {
                        const client = new VerifierClient(address, grpc.credentials.createInsecure());
                        this.log.debug(`Connecting to verifier at ${address}`);
                        await waitForClient(client, this.config.rpc.verifierTimeout);
                        const msg = new VerifierVerifierHandshakeMessage();
                        const resp = await waitForRpc(client, client.verifierVerifierHandshake, msg) as VerifierVerifierHandshakeMessage;
                        const hexBeneficiary = Buffer.from(resp.getBeneficiary_asU8()).toString('hex');
                        if (hexBeneficiary === this.config.beneficiary) {
                            throw new Error(`Attempted to connect to self at ${address}`);
                        }
                        this.log.debug(`Connected to verifier at ${address}, version=${resp.getVersion()} beneficiary=${hexBeneficiary}`)
                        
                        this.connectedSet.add(address);

                        const beneficiary = toBigIntBE(Buffer.from(resp.getBeneficiary_asU8()));
                        const nodeStream =  client.advertiseNode();
                        const blockStream = client.advertiseBlock();
                        const neighborStream = client.advertiseNeighbor();

                        nodeStream.on('close', () => {
                            this.connectedSet.delete(address);
                            client.close();
                        });
            
                        blockStream.on('close', () => {
                            this.connectedSet.delete(address);
                            client.close();
                        });
            
                        neighborStream.on('close', () => {
                            this.connectedSet.delete(address);
                            client.close();
                        });

                        this.neighbors.set(beneficiary, {
                            beneficiary,
                            address,
                            nodeStream,
                            blockStream,
                            neighborStream
                        });
                    } catch (e) {
                        this.log.error(`Failed to connect to verifier at ${address}: ${e}`);
                    }
                }
            }
            await delay(this.config.rpc.rescanInterval);
        }
    }

}