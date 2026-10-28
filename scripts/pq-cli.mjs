import fs from 'node:fs';
import {getBytes,hexlify} from 'ethers';
import {ml_dsa44} from '../artifacts/signers/mldsa-evm.mjs';
import {falcon512} from '../artifacts/signers/falcon-evm.mjs';
import {mlKey,falconKey,decodeFalconSignature} from './keys.mjs';
const [command,first,second]=process.argv.slice(2);
if(command==='keygen') {
  const algorithm=first,file=second;
  if(!file||!['mldsa44-keccak','falcon512-keccak32'].includes(algorithm))throw Error('keygen mldsa44-keccak|falcon512-keccak32 /secure/key.json');
  const signer=algorithm==='mldsa44-keccak'?ml_dsa44:falcon512;
  const keys=signer.keygen();
  const privateRecord={version:1,algorithm,secretKey:hexlify(keys.secretKey),publicKey:hexlify(keys.publicKey)};
  let publicRecord={version:1,algorithm,publicKey:privateRecord.publicKey};
  if(algorithm==='mldsa44-keccak') {
    const k=mlKey(keys.publicKey);
    publicRecord={...publicRecord,parts:[k.wide.slice(0,40962),'0x'+k.wide.slice(40962)],tr:k.tr};
  } else publicRecord={...publicRecord,data:falconKey(keys.publicKey).wire};
  fs.writeFileSync(file,JSON.stringify(privateRecord),{flag:'wx',mode:0o600});
  fs.writeFileSync(file+'.public.json',JSON.stringify(publicRecord,null,2),{flag:'wx',mode:0o644});
  keys.secretKey.fill(0);
  console.log(JSON.stringify({privateFile:file,publicFile:file+'.public.json',algorithm}));
} else if(command==='sign') {
  const file=first,digest=second;
  if(!file||!/^0x[0-9a-fA-F]{64}$/.test(digest??''))throw Error('sign /secure/key.json 0xDIGEST');
  if(fs.statSync(file).mode&0o077)throw Error('Private key permissions must be 0600');
  const k=JSON.parse(fs.readFileSync(file,'utf8'));
  if(k.version!==1)throw Error('Unsupported key version');
  const sk=getBytes(k.secretKey);
  try {
    if(k.algorithm==='mldsa44-keccak')console.log(hexlify(ml_dsa44.sign(getBytes(digest),sk)));
    else if(k.algorithm==='falcon512-keccak32')console.log(decodeFalconSignature(falcon512.sign(getBytes(digest),sk)).wire);
    else throw Error('Unsupported algorithm');
  }finally{sk.fill(0);}
}else throw Error('Usage: pq-cli.mjs keygen ALGORITHM FILE | sign FILE DIGEST');
