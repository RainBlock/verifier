import { RlpDecode, RlpEncode, RlpList } from 'rlp-stream';
import { toBigIntBE, toBufferBE } from 'bigint-buffer';

const ACCOUNT_NONCE = 0;
const ACCOUNT_BALANCE = 1;
const ACCOUNT_STORAGEROOT = 2;
const ACCOUNT_CODEHASH = 3;
export class EthereumAccount {

    static readonly EMPTY_STRING_HASH = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470n;
    static readonly EMPTY_BUFFER_HASH = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421n;

    constructor(public nonce : bigint, public balance : bigint, public codeHash : bigint, public storageRoot : bigint) {

    }

    toRlp() : Buffer {
        let hexBalance = this.balance.toString(16);
        if (hexBalance === '0') {
            hexBalance = '';
        }
        else if (hexBalance.length % 2 === 1) {
            hexBalance = `0${hexBalance}`;
        }

        return RlpEncode([Number(this.nonce), Buffer.from(hexBalance, 'hex'), 
        toBufferBE(this.storageRoot, 32), toBufferBE(this.codeHash, 32)] as RlpList);
    }

    hasCode() {
        return this.codeHash !== EthereumAccount.EMPTY_STRING_HASH;
    }
}

export function EthereumAccountFromBuffer(buf : Buffer) {
    const rlp  = RlpDecode(buf);
    const nonce = toBigIntBE(rlp[ACCOUNT_NONCE] as Buffer);
    const balance = toBigIntBE((rlp[ACCOUNT_BALANCE] as Buffer));
    const codeHash = toBigIntBE(rlp[ACCOUNT_CODEHASH] as Buffer);
    const storageRoot = toBigIntBE(rlp[ACCOUNT_STORAGEROOT] as Buffer);

    return new EthereumAccount(nonce, balance, codeHash, storageRoot);
}