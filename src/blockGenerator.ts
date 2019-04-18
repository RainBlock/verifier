import { EthereumHeader, decodeBlock, EthereumTransaction, CONTRACT_CREATION } from '@rainblock/ethereum-block'
import { ConfigurationFile } from './configFile';
import { encodeBlock, encodeHeaderAsRLP } from '@rainblock/ethereum-block'
import { RlpList, RlpEncode, RlpDecode } from 'rlp-stream/build/src/rlp-stream';
import { EthereumAccount, EthereumAccountFromBuffer } from './ethereumAccount';
import { VerifierStorageClient, UpdateMsg, grpc, UpdateOp, StorageUpdate, TransactionReply, ErrorCode} from '@rainblock/protocol'
import { MerklePatriciaTree, CachedMerklePatriciaTree, MerklePatriciaTreeOptions, MerklePatriciaTreeNode, MerkleKeyNotFoundError } from '@rainblock/merkle-patricia-tree';
import { GethStateDump, GethStateDumpAccount, ImportGethDump } from './gethImport';

import * as fs from 'fs';
import * as path from 'path';
import { hashAsBigInt, hashAsBuffer, HashType } from 'bigint-hash';
import { toBufferBE, toBigIntBE } from 'bigint-buffer';
import { ServiceError } from 'grpc';

const MAX_256_UNSIGNED = 115792089237316195423570985008687907853269984665640564039457584007913129639935n;

export interface BlockGeneratorOptions {
    /** The maximum amount of time the proof of work puzzle takes to solve */
    proofOfWorkTime: number;
    /** The configuration from the configuration file */
    config: ConfigurationFile
    /** The configuratino file directory */
    configDir : string
}

/** Transaction data for processing the transaction and including it in the block. */
export interface TransactionData {
    /** The transaction hash */
    txHash: bigint;
    /** The decoded Ethereum transaction */
    tx : EthereumTransaction;
    /** The decoded RLP transaction */
    txRlp : RlpList;
    /** Binary transaction */
    txBinary : Buffer;
    /** "bag of Proofs" submitted with transaction, keyed by node hash */
    proofs: Map<bigint, MerklePatriciaTreeNode<EthereumAccount>>;
    /** The hash of the "from" account */
    fromHash: Buffer;
    /** The hash of the "to" account */
    toHash: Buffer;
    /** Reply callback */
    callback: (error: ServiceError | null, reply : TransactionReply) => void;
    /** Final error code for sending the reply. */
    errorCode? : ErrorCode;
}

/** Updates for each account */
export interface AccountUpdates {
    /** The operation type */
    op: UpdateOp;
    /** Any storage updates */
    storageUpdates? : StorageUpdate[];
}

/** Internal interface for expressing the result of executing an array of transactions. */
interface ExecutionResult {
    /** New stateRoot from this execution. */
    stateRoot : bigint;
    /** The amount of gas used in executing this transaction. */
    gasUsed: bigint;
    /** The timestamp selected for this transaction. */
    timestamp: bigint;
    /** The ordering of transactions in this execution. */
    order : TransactionData[]
    /** The number of nanoseconds it took to order and execute the transactions. */
    executionTime: bigint;
    /** The write set, keyed by address */
    writeSet: Map<bigint, WriteSetChanges>;
}

/** Per account write set changes. */
interface WriteSetChanges {
    hashedAddress: Buffer;
    balance: bigint;
    nonce: bigint;
}

/** Class responsible for performing actual generation of blocks. */
export class BlockGenerator {

    private blockNumber: bigint;
    private parentHash : bigint;
    private difficulty: bigint;
    private gasLimit : bigint;
    private beneficiary : bigint;
    private tree : CachedMerklePatriciaTree<Buffer, EthereumAccount>;
    private verifiers : VerifierStorageClient[];

    private txQueue : TransactionData[] = [];

    constructor(private logger: Logger, public options : BlockGeneratorOptions, public running: boolean = true) {
        this.blockNumber = 0n;
        this.parentHash = 0n;
        this.difficulty = 0n;
        this.gasLimit = 0n;

        this.beneficiary = BigInt(`0x${options.config.beneficiary}`);
        this.tree = new CachedMerklePatriciaTree<Buffer, EthereumAccount>({
            keyConverter: k => k,
            valueConverter: v => v.toRlp(),
            putCanDelete: false
        }, options.config.pruneDepth);
        this.verifiers = [];

        logger.debug(`New blocks will be assembled between every 0-${options.proofOfWorkTime/1000} seconds`);
    }

    /** Queue a new transaction to be included in the next block. */
    addTransaction(hash: bigint, data: TransactionData) {
        this.txQueue.push(data);
    }

    /** 'Simulate' solving the proof of work puzzle. We'll solve it by delaying its execution */
    solveProofOfWork(executionResult: ExecutionResult, transactionsRoot: bigint) : Promise<EthereumHeader> {
        return new Promise((resolve, reject) => {
            setTimeout(() => resolve({
                parentHash: this.parentHash,
                uncleHash: 0n, // We don't support uncles
                beneficiary: this.beneficiary,
                stateRoot: executionResult.stateRoot,
                transactionsRoot,
                receiptsRoot: 0n, // TODO: we don't support receipts yet.
                logsBloom: Buffer.from([]), // TODO: we don't support receipts yet.
                difficulty: this.difficulty,
                gasLimit: this.gasLimit,
                gasUsed: executionResult.gasUsed,
                timestamp: executionResult.timestamp,
                extraData: Buffer.from("rainblock", "ascii"),
                mixHash: 0n, // TODO: generate a valid mixHash
                nonce: 0n, // TODO: pick a valid nonce
                blockNumber: this.blockNumber
            }), Math.random() * this.options.proofOfWorkTime);
        });
    }

    updateWriteSet(writeSet: Map<bigint, WriteSetChanges>, address: bigint, hashedAddress : Buffer, account: EthereumAccount, usedNodes: Set<bigint>, nodeBag: Map<bigint, MerklePatriciaTreeNode<EthereumAccount>>) {
        writeSet.set(address, {
            hashedAddress,
            nonce: account.nonce,
            balance: account.balance
        })

        // TODO: defer update tree until end
        this.tree.putWithNodeBag(hashedAddress, account, usedNodes, nodeBag);
    }

    /** Order and execute the given transaction map. */
    async orderAndExecuteTransactions(transactions : TransactionData[]) : Promise<ExecutionResult> {
        const order : TransactionData[] = [];
        const writeSet = new Map<bigint, WriteSetChanges>();
        const shareBag = new Map<bigint, MerklePatriciaTreeNode<EthereumAccount>>();
        const nodesUsed = new Set<bigint>();

        const start = process.hrtime.bigint();
        let gasUsed = 0n;
        let i = 0;
        for (const tx of transactions) {
            i++;
            this.logger.debug(`Processing tx ${tx.txHash.toString(16)}`);

            // The proofs to use, (shared bag if turned on)
            const proofs = this.options.config.shareBag ? shareBag : tx.proofs;

            if (this.options.config.shareBag) {
                // add this transaction to the "big" shared node bag
                for (const [hash, node] of tx.proofs) {
                    shareBag.set(hash, node);
                }
            }

            try {
                // First, verify that the FROM account can be found and the
                // nonce in the transaction is one greater than the account
                // nonce.
                let fromAccount : EthereumAccount;
                try {
                    fromAccount = 
                        this.tree.getFromCache(tx.fromHash, nodesUsed, proofs);
                } catch (e) {
                    // TODO: remove nested try-catch
                    if (e instanceof MerkleKeyNotFoundError) {
                        // Generate the account if it doesn't exist
                        if (this.options.config.generateFromAccounts) {
                            fromAccount = new EthereumAccount(tx.tx.nonce, MAX_256_UNSIGNED, EthereumAccount.EMPTY_STRING_HASH, EthereumAccount.EMPTY_BUFFER_HASH);
                        } else {
                            throw new Error(`From account ${tx.tx.from.toString(16)} does not exist!`);
                        }
                    } else {
                        // Pruned tree encountered, we can't proceed
                        throw e;
                    }
                }

                if (!this.options.config.disableNonceCheck && tx.tx.nonce !== fromAccount.nonce) {
                    throw new Error(`From account ${tx.tx.from.toString(16)} had incorrect nonce ${fromAccount.nonce}, expected ${tx.tx.nonce}`);
                }

                // TODO: handle code creation (tx.to == CONTRACT_CREATION)
                if (tx.tx.to === CONTRACT_CREATION) {
                    throw new Error(`tx ${tx.txHash.toString(16)} CONTRACT_CREATION, but CONTRACT_CREATION not yet supported`);
                }

                const toAccount = this.tree.getFromCache(tx.toHash, nodesUsed, proofs);
                if (toAccount === null) {
                    // This means we're going to CREATE this account.
                    this.logger.debug(`tx ${tx.txHash.toString(16)} create new account ${tx.tx.to.toString(16)}`);

                    // TODO: check if account actually has enough funds?
                    const newAccount = new EthereumAccount(0n, tx.tx.value, EthereumAccount.EMPTY_STRING_HASH, EthereumAccount.EMPTY_BUFFER_HASH);
                    fromAccount.nonce += 1n;
                    fromAccount.balance -= tx.tx.value;
                    
                    this.updateWriteSet(writeSet, tx.tx.to, tx.toHash, newAccount, nodesUsed, proofs);
                    this.updateWriteSet(writeSet, tx.tx.from, tx.fromHash, fromAccount, nodesUsed, proofs);
                } else {
                    if (toAccount.hasCode()) {
                        // TODO: execute code
                        this.logger.warn(`To account ${tx.tx.to.toString(16)} Code execution not yet implemented`);
                    } else {
                        // Simple transfer
                        this.logger.debug(`tx ${tx.txHash.toString(16)} transfer ${tx.tx.value.toString(16)} wei from ${tx.tx.from.toString(16)} -> ${tx.tx.to.toString(16)}`);
                        
                        // TODO : accumulate at -end- to avoid repeats
                        // Need our own non-proto format.
                        fromAccount.nonce += 1n;
                        fromAccount.balance -= tx.tx.value;
                        toAccount.balance += tx.tx.value;

                        this.updateWriteSet(writeSet, tx.tx.to, tx.toHash, toAccount, nodesUsed, proofs);
                        this.updateWriteSet(writeSet, tx.tx.from, tx.fromHash, fromAccount, nodesUsed, proofs);
                    }
                }

            tx.errorCode = ErrorCode.ERROR_CODE_SUCCESS;
            order.push(tx);

            } catch (e) {
                if (e instanceof Error) {
                  this.logger.info(`Skipping tx ${tx.txHash.toString(16)} due to ${e.message}`);
                  this.logger.debug(e.stack!);
                } else {
                  this.logger.info(`Skipping tx ${tx.txHash.toString(16)} due to ${e}`);
                }

                tx.errorCode = ErrorCode.ERROR_CODE_INVALID;
            }
        }
        
        /** The miner gets to include their reward */
        // This is a TODO
        const stateRoot = this.tree.rootHash;

        this.logger.debug(`Executed new block ${this.blockNumber} with new root ${stateRoot.toString(16)} using ${gasUsed} gas`);

        return {
            stateRoot: stateRoot,
            gasUsed: gasUsed,
            timestamp: BigInt(Date.now()),
            order,
            writeSet,
            executionTime: process.hrtime.bigint() - start
        }
    }

    /** Calculate the transactions root based on the ordering given. */
    async calculateTransactionsRoot(transactions: TransactionData[]) : Promise<bigint> {
        const tree = new MerklePatriciaTree<number, Buffer>({
            keyConverter: num => Buffer.from(`${num}`, 'utf8'),
            putCanDelete: false
        });
        for (const [idx, tx]  of transactions.entries()) {
            tree.put(idx, tx.txBinary);
        }
        return tree.rootHash;
    }

    /** Propose the block to the list of storage nodes. */
    async proposeBlock(header: EthereumHeader, execution: ExecutionResult) : Promise<bigint> {
        // Encode the new block. We don't support uncles.
        const block = encodeBlock(header, execution.order.map(data => data.txRlp), []);

        const shardRequestList = [];
        // Update each shard
        for (let i = 0; i < 16; i++) {
            const msg = new UpdateMsg();
            msg.setRlpBlock(block);
            msg.setMerkleTreeNodes(
                RlpEncode(this.tree.rootNode.serialize(this.tree.options as MerklePatriciaTreeOptions<{}, EthereumAccount>)));
            // Itereate through the modification list. If it belongs to this shard, add it to the modifications
            for (const [account, changes] of execution.writeSet.entries()) {
                // Get top bit of hashed address
                if (((changes.hashedAddress[0] & 0xF0) >> 4) === i) {
                    const op = new UpdateOp();
                    // note this is the UNHASHED address. The storage unit is expected to re-hash it.
                    op.setAccount(toBufferBE(account, 20));
                    op.setBalance(toBufferBE(changes.balance, 32));
                    op.setNonce(Number(changes.nonce));
                    msg.addOperations(op);
                }
            }
            
            shardRequestList.push(new Promise((resolve, reject) => {
                this.verifiers[i].update(msg, (error, response) => {
                    if (error) {
                        reject(error);
                    } else {
                        if (msg.getOperationsList().length > 0) {
                            this.logger.debug(`Sent ${msg.getOperationsList().length} updates to shard ${i}`);
                        }
                        resolve();
                    }
                });
            }));
        }

        await Promise.all(shardRequestList);
        return hashAsBigInt(HashType.KECCAK256, RlpEncode(encodeHeaderAsRLP(header)));
    }

    /** Initializes the connections to all storage shards. */
    async connectToStorageNodes() {
        // Connect to the storage nodes
        for (let i = 0 ; i < 16; i++) {
            // For now, we only connect to the first node
            const storageNodeAddress = this.options.config.storage[`${i}`];
            this.verifiers[i] = new VerifierStorageClient(storageNodeAddress[0], grpc.credentials.createInsecure());
            await new Promise((resolve, reject) => {
                this.verifiers[i].waitForReady(Date.now() + this.options.config.rpc.storageTimeout, (error=> {
                if (error) {
                    this.logger.warn(`Shard ${i} connection failed: storage node at ${storageNodeAddress}: ${error}`)
                    reject(new Error(`Failed to connect to shard ${i} at ${storageNodeAddress}`))
                } else {
                    this.logger.info(`Shard ${i} connected to storage node at ${storageNodeAddress}`);
                    resolve();
                }
            }))
            });
        }
    }

    /** Initializes the initial state of the verifier to data found in the genesis files set in the config. */
    async loadInitialStateFromGenesisData() {
        const genesisBin = await fs.promises.readFile(path.join(this.options.configDir, this.options.config.genesisBlock));
        const genesisBlock = await decodeBlock(RlpDecode(genesisBin) as RlpList);
        this.parentHash = hashAsBigInt(HashType.KECCAK256, RlpEncode(encodeHeaderAsRLP(genesisBlock.header)));
        this.gasLimit = genesisBlock.header.gasLimit;
        this.difficulty = genesisBlock.header.difficulty;
        this.blockNumber = genesisBlock.header.blockNumber + 1n;

        this.logger.info(`Parent block set to ${this.parentHash.toString(16)}, block number ${genesisBlock.header.blockNumber}`);

        await ImportGethDump(path.join(this.options.configDir, this.options.config.genesisData), this.tree, new Map<bigint, Buffer>());

        // Apparently we need to manually call this
        this.tree.pruneStateCache();

        if (this.tree.rootHash != genesisBlock.header.stateRoot) {
            throw new Error(`Genesis root from block (${genesisBlock.header.stateRoot.toString(16)}) does not match imported root ${this.tree.rootHash.toString(16)}`)
        }

        this.logger.info(`Initialized state to stateRoot ${this.tree.rootHash.toString(16)}`);

    }

    /** Reply to clients with the result of the operations */
    async replyToClients(transactions: TransactionData[]) {
        const replyPromises = [];
        for (const tx of transactions) {
            const reply = new TransactionReply();
            reply.setCode(tx.errorCode === undefined ? ErrorCode.ERROR_CODE_INVALID : tx.errorCode);
            replyPromises.push(new Promise((resolve, reject) => {
                tx.callback(null, reply);
                resolve();
            }));
        }
        await Promise.all(replyPromises);
    }

    /** Every cycle, select as many incoming transactions as possible and
     *  attempt to solve a "proof-of-work" puzzle.
     */
    async generate() {

        // Before we start, load the initial state from the genesis data.
        // In the future, we will be able to pick either loading it from
        // genesis or a storage node.
        await this.loadInitialStateFromGenesisData();

        // Connect to all storage shards and wait for the connections to
        // be active before starting.
        await this.connectToStorageNodes();

        // The main loop, which generates blocks and proposes them to storage, or
        // accepts blocks from other verifiers and verifies them.
        while (this.running) {
            // Take transactions off of the queue to be included into the new block
            const blockTransactions = this.txQueue;
            this.txQueue = [];
            this.logger.info(`Assembling new block ${this.blockNumber.toString()} with ${blockTransactions.length} txes`);

            // Decide on which transactions will be included in the block, order and execute them.
            const executionResult = await this.orderAndExecuteTransactions(blockTransactions);
            this.logger.info(`Assembled ${executionResult.order.length} txes in ${executionResult.executionTime}ns`);

            // Calculate the transactionsRoot
            const transactionsRoot = await this.calculateTransactionsRoot(executionResult.order);

            // Simulate solving the proof of work algorithm.
            const headerPromise = this.solveProofOfWork(executionResult, transactionsRoot);
            // And simultaneously report success/failure to clients
            const replyPromise = this.replyToClients(blockTransactions);

            // Wait for both replies to finish and proof-of-work to be solved.
            await Promise.all([headerPromise, replyPromise]);
            const header = await headerPromise;

            // TODO: in parallel, another verifier may advertise a new solution to us.
            // If that is the case we drop our PoW, and verify their block
            // If their block is correct, we adopt their block as the new parentHash
            // and remove and txHashes from that block currently in our queue.

            this.logger.info(`PoW solution found, proposing new block ${this.blockNumber.toString()}`);
            this.parentHash = await this.proposeBlock(header, executionResult);
            this.logger.info(`New block ${this.parentHash.toString(16)} successfully proposed, adopting as parent`);
            this.blockNumber++;

            // Prune the state cache.
            this.tree.pruneStateCache();
        }
    }
}