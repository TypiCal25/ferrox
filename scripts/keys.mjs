import fs from 'node:fs';
import {shake128, shake256} from '@noble/hashes/sha3.js';
import {AbiCoder, concat, hexlify, toBeHex} from 'ethers';

export function unpackBits(bytes, bits, count) {
  let accumulator=0n, available=0, pos=0; const mask=(1n<<BigInt(bits))-1n, out=[];
  while (out.length<count) {
    while (available<bits) { accumulator |= BigInt(bytes[pos++]) << BigInt(available); available+=8; }
    out.push(Number(accumulator&mask)); accumulator >>= BigInt(bits); available-=bits;
  }
  return out;
}
export function packWords(a, bits) {
  const count=256/bits, out=[];
  for(let i=0;i<a.length;i+=count) {
    let w=0n; for(let j=0;j<count;j++) w |= BigInt(a[i+j]) << BigInt(bits*j);
    out.push(w);
  }
  return out;
}
export function nttML(a) {
  const q=8380417; a=a.slice();
  const pow=(x,e)=>{ let v=1n; for(;e;e>>=1,x=x*x%8380417n) if(e&1)v=v*x%8380417n; return Number(v); };
  const reverse=i=>Number.parseInt(i.toString(2).padStart(8,'0').split('').reverse().join(''),2);
  let k=1;
  for(let len=128;len>=1;len>>=1) for(let start=0;start<256;start+=2*len) {
    const zeta=pow(1753n,reverse(k++));
    for(let j=start;j<start+len;j++){const v=zeta*a[j+len]%q,u=a[j];a[j]=(u+v)%q;a[j+len]=(u-v+q)%q;}
  }
  return a;
}
export function inverseML(a) {
  const q=8380417,mod=x=>(x%q+q)%q;
  const pow=(x,e)=>{let y=1n;for(;e;e>>=1,x=x*x%8380417n)if(e&1)y=y*x%8380417n;return Number(y);};
  const reverse=i=>Number.parseInt(i.toString(2).padStart(8,'0').split('').reverse().join(''),2);
  a=a.map(mod);let k=255;
  for(let len=1;len<=128;len*=2)for(let start=0;start<256;start+=2*len){
    const zeta=mod(-pow(1753n,reverse(k--)));
    for(let j=start;j<start+len;j++){const u=a[j],v=a[j+len];a[j]=mod(u+v);a[j+len]=mod((u-v)*zeta);}
  }
  return a.map(x=>x*8347681%q);
}
export function mlKey(publicKey) {
  if(publicKey.length!==1312)throw Error('ML-DSA-44 key length');
  const rho=publicKey.subarray(0,32), polys=[];
  for(let row=0;row<4;row++)for(let col=0;col<4;col++) {
    // Generate ample SHAKE output; rejection loop is exact, never biased by modulo.
    let length=1024, a;
    do {
      const stream=shake128(new Uint8Array([...rho,col,row]),{dkLen:length}); a=[];
      for(let i=0;i+2<stream.length && a.length<256;i+=3){let x=(stream[i]|stream[i+1]<<8|stream[i+2]<<16)&0x7fffff;if(x<8380417)a.push(x);}
      length*=2;
    } while(a.length<256);
    polys.push(packWords(a,32));
  }
  const t=unpackBits(publicKey.subarray(32),10,1024);
  for(let i=0;i<4;i++)polys.push(packWords(nttML(t.slice(i*256,(i+1)*256).map(x=>x*8192%8380417)),32));
  const tr=hexlify(shake256(publicKey,{dkLen:64}));
  const coefficient=(poly,i)=>Number((poly[i>>3]>>BigInt(32*(i&7)))&0xffffffffn);
  const transposed=[];
  for(let col=0;col<5;col++)for(let i=0;i<256;i+=2){
    const fields=[];
    for(let j=0;j<2;j++)for(let row=0;row<4;row++)fields.push(coefficient(polys[col<4?row*4+col:16+row],i+j));
    transposed.push(toBeHex(packWords(fields,32)[0],32));
  }
  const compact=concat([tr,...transposed]);
  const wide=[];
  for(let col=0;col<5;col++)for(let i=0;i<256;i++){
    const fields=Array.from({length:4},(_,row)=>coefficient(polys[col<4?row*4+col:16+row],i));
    wide.push(toBeHex(packWords(fields,64)[0],32));
  }
  const coder=AbiCoder.defaultAbiCoder();
  const aHat=Array.from({length:4},(_,i)=>polys.slice(i*4,i*4+4));
  // Upstream stores nested ABI encodings in a tuple of bytes.
  const upstream=coder.encode(['bytes','bytes','bytes'],[
    coder.encode(['uint256[][][]'],[aHat]),tr,coder.encode(['uint256[][]'],[polys.slice(16)])
  ]);
  return {compact,wide:concat(wide),upstream,polys,tr};
}
export function decodeFalconSignature(signature) {
  if(signature[0]!==0x39)throw Error('Falcon-512 signature header');
  const salt=signature.subarray(1,41), bytes=signature.subarray(41); let pos=0;
  const bit=()=>{if(pos>=bytes.length*8)throw Error('Truncated Falcon signature');return (bytes[pos>>3]>>(7-(pos++&7)))&1;};
  const s2=[];
  for(let i=0;i<512;i++){
    const sign=bit();let v=0;for(let k=0;k<7;k++)v=(v<<1)|bit();
    let hi=0;while(!bit()){if(++hi>15)throw Error('Falcon coefficient overflow');}
    v+=hi*128;if(sign&&v===0)throw Error('negative zero');s2.push(sign?(12289-v)%12289:v);
  }
  const packed=packWords(s2,16);
  return {salt:hexlify(salt),s2:packed,wire:concat([salt,...packed.map(w=>toBeHex(w,32))])};
}
export function falconKey(publicKey) {
  if(publicKey.length!==897||publicKey[0]!==9)throw Error('Falcon-512 key');
  // Falcon's public key uses big-endian 14-bit fields.
  let p=0;const a=[];for(let i=0;i<512;i++){let w=0;for(let j=0;j<14;j++){w=(w<<1)|((publicKey[1+(p>>3)]>>(7-(p++&7)))&1);}if(w>=12289)throw Error('key range');a.push(w);}
  const source=fs.readFileSync('vendor/ethfalcon/src/ZKNOX_NTT_falcon_packed.sol','utf8');
  const first=source.match(/uint256\[32\] memory psirev = \[([\s\S]*?)\];/)[1];
  const tables=first.match(/0x[0-9a-fA-F]+/g).map(BigInt);
  const tw=Array.from({length:512},(_,i)=>Number((tables[i>>4]>>BigInt(16*(i&15)))&65535n));
  // Full NTT public key: the pinned eight-lane kernel expects all nine layers.
  let t=512;
  for(let m=1;m<512;m*=2){t>>=1;for(let i=0;i<m;i++)for(let j=2*i*t;j<2*i*t+t;j++){const u=a[j],v=a[j+t]*tw[m+i]%12289;a[j]=(u+v)%12289;a[j+t]=(u-v+12289)%12289;}}
  const words=packWords(a,16);
  return {words,wire:concat(words.map(w=>toBeHex(w,32)))};
}
