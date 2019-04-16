import { ConfigurationFile } from "./configFile";

export interface NeighborData {

}

// The NetworkLearner manages connections with and learns about updates from other verifiers in the network.
export class NetworkLearner {

    neighborMap : Map<bigint, NeighborData> = new Map();

    constructor(public config : ConfigurationFile) {
        
    }


}