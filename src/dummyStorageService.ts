import {  IVerifierStorageServer, UpdateMsg, google_protobuf_empty_pb, grpc} from '@rainblock/protocol'

export class DummyStorageServer implements IVerifierStorageServer {

    constructor(private logger : Logger) {
        
    }

    async update(call: grpc.ServerUnaryCall<UpdateMsg>, 
        callback: grpc.sendUnaryData<google_protobuf_empty_pb.Empty>) {
        this.logger.debug(`Got message from ${call.getPeer()}`);
        callback(null, new google_protobuf_empty_pb.Empty());
    }
}