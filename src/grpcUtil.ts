import { grpc } from '@rainblock/protocol';

export function waitForClient(client : grpc.Client, timeout: number) : Promise<void> {
    return new Promise((resolve, reject) => {
        client.waitForReady(Date.now() + timeout, (err) => {
            if (err) {
                reject(err);
            }
            resolve();
        });
    });
}

export function waitForRpc<R,S>(client : grpc.Client, rpc : (request: R, callback : (error : grpc.ServiceError | null, response : S) => void) => grpc.ClientUnaryCall, request : R) : Promise<S> {
    return new Promise<S>((resolve, reject) => {
        rpc.call(client, request, (error : grpc.ServiceError | null, response : S) => {
            if (error) {
                reject(error);
            }
            resolve(response as S);
        });
    });
}

export function delay(ms : number) : Promise<void> {
    return new Promise((resolve, reject) => {
        setTimeout(() => resolve(), ms);
    })
}