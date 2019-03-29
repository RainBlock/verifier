
export interface GethStateDumpAccount {
    balance : string;
    nonce : number;
    root: string;
    codeHash: string;
    code: string;
    storage: { [key : string] : string};
}

export interface GethStateDump {
    root : string;
    accounts: { [id : string] : GethStateDumpAccount };
}