/** An interface which defines the contents of the parsed YAML configuration file. */
export interface ConfigurationFile {
    storage: StorageNodes
    verifiers: string[];
    rpc: RpcSettings
    /** Hex string indicating account number of beneficiary */
    beneficiary: string;
    /** Block reward size, in wei */
    blockReward: number;
    /** Path to the genesis block file, relative to the config file */
    genesisBlock: string;
    /** Path to the genesis data file, exported by `geth dump`, relative to the config file */
    genesisData : string;
    /** Whether or not to disable nonce checking. */
    disableNonceCheck? : boolean;
    /** If the from account doesn't exist, generate it instead of rejecting it. */
    generateFromAccounts? : boolean;
    /** Pruning depth for the cached merkle tree */
    pruneDepth? : number;
}

/** RPC settings */
export interface RpcSettings {
    /** Timeout for storage node RPCs */
    storageTimeout: number;
}

/** The list of storage nodes */
export interface StorageNodes {
    /** Shard 0 storage node addresses */
    "0": string[];
    /** Shard 1 storage node addresses */
    "1": string[];
    /** Shard 2 storage node addresses */
    "2": string[];
    /** Shard 3 storage node addresses */
    "3": string[];
    /** Shard 4 storage node addresses */
    "4": string[];
    /** Shard 5 storage node addresses */
    "5": string[];
    /** Shard 6 storage node addresses */
    "6": string[];
    /** Shard 7 storage node addresses */
    "7": string[];
    /** Shard 8 storage node addresses */
    "8": string[];
    /** Shard 9 storage node addresses */
    "9": string[];
    /** Shard 10 storage node addresses */
    "10": string[];
    /** Shard 11 storage node addresses */
    "11": string[];
    /** Shard 12 storage node addresses */
    "12": string[];
    /** Shard 13 storage node addresses */
    "13": string[];
    /** Shard 14 storage node addresses */
    "14": string[];
    /** Shard 15 storage node addresses */
    "15": string[];
    // Indexer
    [key: string]: string[];
}