import {randomBytes} from 'node:crypto';
import {keccak256, concat, toBeHex, getBytes, id} from 'ethers';

const domains = window => Object.fromEntries(['CHAIN','LEAF','NODE','SECRET'].map(role=>[role,id(`PQWALLET/KWOTS${window}/${role}/v1`)]));
function chain(value,seed,leaf,i,start,end,window=8) {
  const {CHAIN}=domains(window);
  for(let step=start;step<end;step++)value=keccak256(concat([CHAIN,seed,toBeHex((BigInt(leaf)<<32n)|(BigInt(i)<<8n)|BigInt(step),32),value]));
  return value;
}
function secretAt(secret,seed,leaf,i,window){return keccak256(concat([domains(window).SECRET,secret,seed,toBeHex(leaf,32),toBeHex(i,32)]));}
export function makeWotsTree(height=4, secret=toBeHex(BigInt('0x'+randomBytes(32).toString('hex')),32),seed=toBeHex(BigInt('0x'+randomBytes(32).toString('hex')),32),window=8) {
  if(![8,16].includes(window))throw Error('window must be 8 or 16');
  const count=window===8?90:67,{LEAF,NODE}=domains(window);
  if(!Number.isInteger(height)||height<0||height>20)throw Error('height must be 0..20');
  const leaves=[];
  for(let leaf=0;leaf<2**height;leaf++) {
    const endpoints=Array.from({length:count},(_,i)=>chain(secretAt(secret,seed,leaf,i,window),seed,leaf,i,0,window-1,window));
    leaves.push(keccak256(concat([LEAF,seed,toBeHex(leaf,32),...endpoints])));
  }
  const levels=[leaves];
  for(let level=0;level<height;level++) {
    const previous=levels.at(-1),next=[];
    for(let i=0;i<previous.length;i+=2)next.push(keccak256(concat([NODE,toBeHex(level,32),previous[i],previous[i+1]])));
    levels.push(next);
  }
  return {version:`KWOTS${window}-Merkle-v1`,window,height,secret,seed,levels,root:levels.at(-1)[0],nextLeaf:0};
}
export function wotsDigits(digest,window=8) {
  if(window===8) {
    if(!/^0x[0-9a-fA-F]{64}$/.test(digest))throw Error('digest must be bytes32');
    const value=BigInt(digest),digits=Array.from({length:86},(_,i)=>Number((value>>BigInt(255-3*i))&7n));
    const sum=digits.reduce((s,d)=>s+7-d,0);
    return [...digits,(sum>>9)&7,(sum>>6)&7,(sum>>3)&7,sum&7];
  }
  const digits=[...digest.slice(2)].map(x=>parseInt(x,16));
  if(digits.length!==64||digits.some(Number.isNaN))throw Error('digest must be bytes32');
  const checksum=digits.reduce((s,d)=>s+15-d,0);
  return [...digits,(checksum>>8)&15,(checksum>>4)&15,checksum&15];
}
/// Low-level fixture helper. Production callers MUST reserve leaf state durably first.
export function signWotsAt(tree,digest,leaf) {
  if(!Number.isInteger(leaf)||leaf<0||leaf>=2**tree.height)throw Error('leaf exhausted/out of range');
  const window=tree.window, digits=wotsDigits(digest,window);
  const values=digits.map((d,i)=>chain(secretAt(tree.secret,tree.seed,leaf,i,window),tree.seed,leaf,i,0,d,window));
  const proof=[];for(let l=0;l<tree.height;l++)proof.push(tree.levels[l][(leaf>>l)^1]);
  return concat([toBeHex(leaf,4),tree.seed,...values,...proof]);
}

// Independent readable verifier used for differential tests of the assembly verifier.
export function verifyWots(root,digest,signature,window=8) {
  const {LEAF,NODE}=domains(window),base=window===8?2916:2180;
  try {
    const b=getBytes(signature),height=(b.length-base)/32;
    if(!Number.isInteger(height)||height<0||height>20)return false;
    const leaf=new DataView(b.buffer,b.byteOffset,4).getUint32(0),seed=toBeHex(BigInt('0x'+Buffer.from(b.subarray(4,36)).toString('hex')),32);
    if(leaf>=2**height)return false;
    const values=wotsDigits(digest,window).map((d,i)=>chain('0x'+Buffer.from(b.subarray(36+i*32,68+i*32)).toString('hex'),seed,leaf,i,d,window-1,window));
    let node=keccak256(concat([LEAF,seed,toBeHex(leaf,32),...values]));
    for(let level=0;level<height;level++) {
      const sibling=b.subarray(base+level*32,base+32+level*32);
      node=keccak256(concat([NODE,toBeHex(level,32),...((leaf>>level)&1?[sibling,node]:[node,sibling])]));
    }
    return node===root;
  }catch{return false;}
}
