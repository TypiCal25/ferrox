import fs from 'node:fs';
import assert from 'node:assert/strict';
import {id, hexlify, getBytes, toBeHex, concat, keccak256} from 'ethers';
import {ml_dsa44 as standardML} from '@noble/post-quantum/ml-dsa.js';
import {falcon512 as standardFalcon} from '@noble/post-quantum/falcon.js';
import {ml_dsa44 as evmML} from '../artifacts/signers/mldsa-evm.mjs';
import {falcon512 as evmFalcon} from '../artifacts/signers/falcon-evm.mjs';
import {falcon512 as upstreamEVMFalcon} from '../artifacts/signers/falcon-upstream-evm.mjs';
import {keccakCTR} from '../scripts/keccak-ctr.mjs';
import {mlKey,falconKey,decodeFalconSignature,packWords,nttML,inverseML} from '../scripts/keys.mjs';
import {makeWotsTree,signWotsAt,verifyWots} from '../scripts/wots.mjs';
import {createEVM} from './evm.mjs';

const evm=await createEVM(),bench={};let checks=0;
const check=(v,message)=>{assert(v,message);checks++;};
const equal=(a,b,message)=>{assert.deepEqual(a,b,message);checks++;};
const mutate=(hex,index=0)=>{const b=getBytes(hex);b[index]^=1;return hexlify(b);};
const pointer=a=>toBeHex(BigInt(a),32);
const digest=id('PQC test message');
console.log('Generating reproducible test-only keys');
const ml=standardML.keygen(new Uint8Array(32).fill(7));
const falcon=standardFalcon.keygen(new Uint8Array(48).fill(9));
const mlExpanded=mlKey(ml.publicKey),falconExpanded=falconKey(falcon.publicKey);
const tree=makeWotsTree(3,toBeHex(123,32),toBeHex(456,32));
const hashV=await evm.deploy('KeccakWOTS'),mlV=await evm.deploy('MLDSAKeccak'),falconV=await evm.deploy('FalconKeccak');
const mlPart0=await evm.deploy('KeyData',[mlExpanded.wide.slice(0,2+20480*2)]);
const mlPart1=await evm.deploy('KeyData',['0x'+mlExpanded.wide.slice(2+20480*2)]);
const mlData=await evm.deploy('KeyData',[concat([mlPart0.address,mlPart1.address,mlExpanded.tr])]),falconData=await evm.deploy('KeyData',[falconExpanded.wire]);
const mlPointer=pointer(mlData.address),falconPointer=pointer(falconData.address);
check((await evm.call(mlV,'validateKey',[mlPointer]))[0],'ML key validation');
check((await evm.call(falconV,'validateKey',[falconPointer]))[0],'Falcon key validation');
const invalidML=getBytes(mlExpanded.wide.slice(0,40962));
invalidML.set(getBytes(toBeHex(8380417,8)),24);
const invalidMLPart=await evm.deploy('KeyData',[invalidML]);
const invalidMLDescriptor=await evm.deploy('KeyData',[concat([invalidMLPart.address,mlPart1.address,mlExpanded.tr])]);
check(!(await evm.call(mlV,'validateKey',[pointer(invalidMLDescriptor.address)]))[0],'ML key coefficient bound');
const invalidFalcon=getBytes(falconExpanded.wire);invalidFalcon[30]=0x30;invalidFalcon[31]=0x01;
const invalidFalconKey=await evm.deploy('KeyData',[invalidFalcon]);
check(!(await evm.call(falconV,'validateKey',[pointer(invalidFalconKey.address)]))[0],'Falcon key coefficient bound');
const refChallenge=await evm.deploy('ReferenceChallenge');
for(let i=0;i<64;i++) {
  const seed=id('challenge-'+i);
  const ours=(await evm.call(mlV,'challenge',[seed]))[0];
  const reference=(await evm.call(refChallenge,'challenge',[seed]))[0];
  equal([...ours],[...reference],'packed challenge mismatch');
}
bench.challengeReference=await evm.send(refChallenge,'challenge',[digest]);
bench.challengeOptimized=await evm.send(mlV,'challenge',[digest]);
console.log('Packed challenge matches reference');

const nttHarness=await evm.deploy('NTTTestHarness');
const researchHarness=await evm.deploy('ResearchNTTHarness');
const unpack=(words,bits,count)=>Array.from({length:count},(_,i)=>Number((words[Math.floor(i/(256/bits))]>>BigInt(bits*(i%(256/bits))))&((1n<<BigInt(bits))-1n)));
for(let sample=0;sample<8;sample++) {
  const polys=Array.from({length:5},(_,r)=>Array.from({length:256},(_,i)=>sample===0?0:sample===1?8380416:Number(BigInt(id(`ntt/${sample}/${r}/${i}`))%8380417n)));
  const inputs=polys.map(p=>packWords(p,64));
  const actual=(await evm.call(researchHarness,'forward',[inputs.slice(0,4),inputs[4]]))[0];
  for(let r=0;r<5;r++) {
    const expected=nttML(polys[r]);
    for(let i=0;i<256;i++){
      const v=Number((actual[i]>>BigInt(r*51))&((1n<<51n)-1n));
      check(v>=0&&v<22*8380417,'forward bound');equal(v%8380417,expected[i],'forward scalar differential');
    }
  }
  const raw=Array.from({length:4},(_,r)=>Array.from({length:256},(_,i)=>sample===0?0:sample===1?8380417*(2**30)-1:Number(BigInt(id(`inverse/${sample}/${r}/${i}`))%BigInt(8380417*(2**30)))));
  const packed=Array.from({length:256},(_,i)=>raw.reduce((w,p,r)=>w|(BigInt(p[i])<<BigInt(64*r)),0n));
  const inverse=(await evm.call(researchHarness,'inverse',[packed]))[0];
  for(let r=0;r<4;r++)equal(unpack(inverse[r],64,256),inverseML(raw[r]),'inverse scalar differential');
}
for(let sample=0;sample<8;sample++) {
  const values=Array.from({length:5},(_,r)=>Array.from({length:256},(_,i)=>sample===0?0:sample===1?17*8380417-1:Number(BigInt(id(`matrix/${sample}/${r}/${i}`))%BigInt(17*8380417))));
  const input=values.map(p=>packWords(p,64));
  const actual=(await evm.call(nttHarness,'matvec',[mlExpanded.wide,input.slice(0,4),input[4]]))[0];
  const coeff=(p,i)=>(p[i>>3]>>BigInt(32*(i&7)))&0xffffffffn;
  for(let i=0;i<256;i++)for(let r=0;r<4;r++){
    let expected=8380417n*(1n<<28n)-BigInt(values[4][i])*coeff(mlExpanded.polys[16+r],i);
    for(let col=0;col<4;col++)expected+=BigInt(values[col][i])*coeff(mlExpanded.polys[r*4+col],i);
    equal((actual[r][i>>2]>>BigInt(64*(i&3)))&((1n<<64n)-1n),expected,'matvec scalar differential');
    check(expected>=0&&expected<8380417n*(1n<<30n),'matrix accumulator bound');
  }
}
console.log('Parallel NTT and matrix arithmetic match scalar references, including saturated bounds');

const hashSig=signWotsAt(tree,digest,0);
check(verifyWots(tree.root,digest,hashSig),'JS WOTS reference');
check((await evm.call(hashV,'verify',[tree.root,digest,hashSig]))[0],'WOTS verification');
bench.wots=await evm.send(hashV,'verify',[tree.root,digest,hashSig]);
const wots16=await evm.deploy('KeccakWOTS16');
const tree16=makeWotsTree(3,toBeHex(123,32),toBeHex(456,32),16);
const sig16=signWotsAt(tree16,digest,0);
check((await evm.call(wots16,'verify',[tree16.root,digest,sig16]))[0],'WOTS16 comparison');
bench.wots16=await evm.send(wots16,'verify',[tree16.root,digest,sig16]);
for(const sig of [mutate(hashSig,70),hashSig.slice(0,-2),'0x'])check(!(await evm.call(hashV,'verify',[tree.root,digest,sig]))[0],'bad WOTS accepted');
console.log('WOTS signing and verification pass');

const mlSig=evmML.sign(getBytes(digest),ml.secretKey,{extraEntropy:false});
check(evmML.verify(mlSig,getBytes(digest),ml.publicKey),'JS ML reference');
check((await evm.call(mlV,'verify',[mlPointer,digest,mlSig]))[0],'ML verification');
bench.mldsa=await evm.send(mlV,'verify',[mlPointer,digest,mlSig]);
check(!(await evm.call(mlV,'verify',[mlPointer,mutate(digest),mlSig]))[0],'ML wrong message');
check(!(await evm.call(mlV,'verify',[mlPointer,digest,mutate(hexlify(mlSig),0)]))[0],'ML bad challenge');
console.log('ML-DSA-like signing and verification pass');

const falconSig=evmFalcon.sign(getBytes(digest),falcon.secretKey,{extraEntropy:false});
check(evmFalcon.verify(falconSig,getBytes(digest),falcon.publicKey),'JS Falcon reference');
const decodedFalcon=decodeFalconSignature(falconSig);
check((await evm.call(falconV,'verify',[falconPointer,digest,decodedFalcon.wire]))[0],'Falcon verification');
bench.falcon=await evm.send(falconV,'verify',[falconPointer,digest,decodedFalcon.wire]);
check(!(await evm.call(falconV,'verify',[falconPointer,mutate(digest),decodedFalcon.wire]))[0],'Falcon wrong message');
check(!(await evm.call(falconV,'verify',[falconPointer,digest,mutate(decodedFalcon.wire,0)]))[0],'Falcon wrong salt');
console.log('Falcon-like signing and verification pass');

for(let i=0;i<8;i++) {
  const d=id('end-to-end vector '+i);
  const m=evmML.sign(getBytes(d),ml.secretKey,{extraEntropy:false});
  check((await evm.call(mlV,'verify',[mlPointer,d,m]))[0],'ML multi-message vector');
  check(!(await evm.call(mlV,'verify',[mlPointer,d,mutate(hexlify(m),32+i)]))[0],'ML mutated vector');
  const f=decodeFalconSignature(evmFalcon.sign(getBytes(d),falcon.secretKey,{extraEntropy:false}));
  check((await evm.call(falconV,'verify',[falconPointer,d,f.wire]))[0],'Falcon multi-message vector');
  check(!(await evm.call(falconV,'verify',[falconPointer,mutate(d),f.wire]))[0],'Falcon mutated vector');
}
const forcedSalt=getBytes('0x0000000000000000000000000000000000000000000000000000000000000000000000000000020b');
const stream=keccakCTR.create().update(getBytes(id('PQWALLET/FALCON512/POINT32/v1'))).update(forcedSalt).update(getBytes(digest)).xof(2048);
check(new DataView(stream.buffer).getUint32(471*4)>=4294956344,'rejection-path fixture');
const forcedSignature=decodeFalconSignature(evmFalcon.sign(getBytes(digest),falcon.secretKey,{random:len=>len===40?forcedSalt.slice():new Uint8Array(len).fill(13)}));
check((await evm.call(falconV,'verify',[falconPointer,digest,forcedSignature.wire]))[0],'Falcon rejection/unaligned/tail path');
const badZ=mlSig.slice();badZ[32]=0;badZ[33]=0;badZ[34]&=0xfc;
check(!(await evm.call(mlV,'verify',[mlPointer,digest,badZ]))[0],'ML norm boundary');
const badHint=mlSig.slice();badHint[2416]=81;
check(!(await evm.call(mlV,'verify',[mlPointer,digest,badHint]))[0],'ML hint bound');
for(const sig of ['0x',hexlify(mlSig.slice(0,-1)),concat([mlSig,'0x00'])])check(!(await evm.call(mlV,'verify',[mlPointer,digest,sig]))[0],'ML noncanonical size');
const badFalcon=getBytes(decodedFalcon.wire);badFalcon[70]=0x30;badFalcon[71]=0x01;
check(!(await evm.call(falconV,'verify',[falconPointer,digest,badFalcon]))[0],'Falcon coefficient q');
for(const sig of ['0x',decodedFalcon.wire.slice(0,-2),concat([decodedFalcon.wire,'0x00'])])check(!(await evm.call(falconV,'verify',[falconPointer,digest,sig]))[0],'Falcon noncanonical size');

// Baselines use the same key and compiler profile, standard SHAKE helpers included.
async function helper(file) {
  const runtime=fs.readFileSync(file,'utf8').trim().replace(/^0x/,'');
  return (await evm.tx(null,concat(['0x61',toBeHex(runtime.length/2,2),'0x8061000b5f395ff3','0x'+runtime]))).address;
}
const baselineML=await evm.deploy('ZKNOX_ethdilithium');
const baselineKey=await evm.deploy('KeyData',[mlExpanded.upstream]);
check((await evm.call(baselineML,'verify(bytes,bytes,bytes,bytes)',[baselineKey.address,digest,mlSig,'0x']))[0],'upstream ETH signature');
bench.mldsaUpstreamKeccak=await evm.send(baselineML,'verify(bytes,bytes,bytes,bytes)',[baselineKey.address,digest,mlSig,'0x']);
const mlHelper=await helper('vendor/ethdilithium/test/f1600_170.hex');
const baselineStandardML=await evm.deploy('ZKNOX_dilithium',[mlHelper]);
const mlStandardSig=standardML.sign(getBytes(digest),ml.secretKey,{extraEntropy:false});
check((await evm.call(baselineStandardML,'verify(bytes,bytes,bytes,bytes)',[baselineKey.address,digest,mlStandardSig,'0x']))[0],'standard ML signature');
bench.mldsaUpstreamStandard=await evm.send(baselineStandardML,'verify(bytes,bytes,bytes,bytes)',[baselineKey.address,digest,mlStandardSig,'0x']);
const falconHelper=await helper('vendor/ethfalcon/test/f1600_zknox.hex');
const baselineFalcon=await evm.deploy('ZKNOX_falcon8',[falconHelper]);
const standardFalconSig=decodeFalconSignature(standardFalcon.sign(getBytes(digest),falcon.secretKey,{extraEntropy:false}));
check((await evm.call(baselineFalcon,'verify',[digest,standardFalconSig.salt,standardFalconSig.s2,falconExpanded.words]))[0],'standard Falcon signature');
bench.falconUpstreamStandard=await evm.send(baselineFalcon,'verify',[digest,standardFalconSig.salt,standardFalconSig.s2,falconExpanded.words]);
const baselineEVMFalcon=await evm.deploy('ZKNOX_ethfalcon');
const upstreamFalconSig=decodeFalconSignature(upstreamEVMFalcon.sign(getBytes(digest),falcon.secretKey,{extraEntropy:false}));
check((await evm.call(baselineEVMFalcon,'verify(bytes,bytes,uint256[],uint256[])',[digest,upstreamFalconSig.salt,upstreamFalconSig.s2,falconExpanded.words]))[0],'upstream Keccak Falcon signature');
bench.falconUpstreamKeccak=await evm.send(baselineEVMFalcon,'verify(bytes,bytes,uint256[],uint256[])',[digest,upstreamFalconSig.salt,upstreamFalconSig.s2,falconExpanded.words]);
check(!(await evm.call(mlV,'verify',[mlPointer,digest,mlStandardSig]))[0],'ML algorithm separation');
check(!(await evm.call(falconV,'verify',[falconPointer,digest,concat([standardFalconSig.salt,...standardFalconSig.s2.map(w=>toBeHex(w,32))])]))[0],'Falcon algorithm separation');
console.log('Upstream standard and custom baselines pass');

const target=await evm.deploy('Target');
const owners=[{key:tree.root,algorithm:1},{key:mlPointer,algorithm:2},{key:falconPointer,algorithm:3}];
const policy={threshold:3,hashMin:1,mlMin:1,falconMin:1};
const wallet=await evm.deploy('PQWallet',[[hashV.address,mlV.address,falconV.address],owners,policy]);
const deadline=1840000000n;
const calls=[{target:target.address,value:0,data:target.interface.encodeFunctionData('set',[42])}];
async function approvals(calls,leaf,deadlineValue=deadline) {
  const d=(await evm.call(wallet,'digest',[calls,deadlineValue]))[0];
  return [
    {owner:0,signature:signWotsAt(tree,d,leaf)},
    {owner:1,signature:hexlify(evmML.sign(getBytes(d),ml.secretKey,{extraEntropy:false}))},
    {owner:2,signature:decodeFalconSignature(evmFalcon.sign(getBytes(d),falcon.secretKey,{extraEntropy:false})).wire}
  ];
}
const firstApprovals=await approvals(calls,0);
bench.multisig3of3=await evm.send(wallet,'execute',[calls,deadline,firstApprovals]);
equal((await evm.call(target,'value'))[0],42n,'execution');
equal((await evm.call(wallet,'nonce'))[0],1n,'nonce increment');
equal((await evm.call(wallet,'nextLeafForRoot',[tree.root]))[0],1n,'leaf burned');
await evm.send(wallet,'execute',[calls,deadline,firstApprovals],{revert:true});checks++;
const secondApprovals=await approvals(calls,1);
await evm.send(wallet,'execute',[calls,deadline,[secondApprovals[0],secondApprovals[0],secondApprovals[2]]],{revert:true});checks++;
await evm.send(wallet,'execute',[calls,deadline,[...secondApprovals].reverse()],{revert:true});checks++;
await evm.send(wallet,'execute',[calls,deadline,secondApprovals.slice(1)],{revert:true});checks++;
const corrupted=structuredClone(secondApprovals);corrupted[1].signature=mutate(corrupted[1].signature);
await evm.send(wallet,'execute',[calls,deadline,corrupted],{revert:true});checks++;
equal((await evm.call(wallet,'nonce'))[0],1n,'failed tx preserves nonce');
equal((await evm.call(wallet,'nextLeafForRoot',[tree.root]))[0],1n,'failed tx rolls back on-chain leaf state');
await evm.send(wallet,'configure',[owners,policy],{revert:true});checks++;
await evm.send(wallet,'execute',[calls,1,secondApprovals],{revert:true});checks++;
const failCalls=[{target:target.address,value:0,data:target.interface.encodeFunctionData('set',[123])},{target:target.address,value:0,data:target.interface.encodeFunctionData('fail')}];
await evm.send(wallet,'execute',[failCalls,deadline,await approvals(failCalls,2)],{revert:true});checks++;
equal((await evm.call(target,'value'))[0],42n,'batch failure rolls back earlier external effects');
equal((await evm.call(wallet,'nonce'))[0],1n,'batch failure rolls back nonce');
const removeCalls=[{target:wallet.address,value:0,data:wallet.interface.encodeFunctionData('configure',[owners.slice(1),{threshold:2,hashMin:0,mlMin:1,falconMin:1}])}];
await evm.send(wallet,'execute',[removeCalls,deadline,await approvals(removeCalls,3)]);
equal((await evm.call(wallet,'ownerCount'))[0],2n,'owner removal');
const restoreCalls=[{target:wallet.address,value:0,data:wallet.interface.encodeFunctionData('configure',[owners,policy])}];
const restoreDigest=(await evm.call(wallet,'digest',[restoreCalls,deadline]))[0];
const restoreApprovals=[
  {owner:0,signature:hexlify(evmML.sign(getBytes(restoreDigest),ml.secretKey,{extraEntropy:false}))},
  {owner:1,signature:decodeFalconSignature(evmFalcon.sign(getBytes(restoreDigest),falcon.secretKey,{extraEntropy:false})).wire}
];
await evm.send(wallet,'execute',[restoreCalls,deadline,restoreApprovals]);
equal((await evm.call(wallet,'epoch'))[0],3n,'configuration epoch');
equal((await evm.call(wallet,'nextLeafForRoot',[tree.root]))[0],4n,'removed/re-added root preserves used leaves');
// Deliberate misuse fixture: a newly signed message with an already used OTS index.
await evm.send(wallet,'execute',[calls,deadline,await approvals(calls,0)],{revert:true});checks++;
const inner=wallet.interface.encodeFunctionData('execute',[calls,deadline,[]]);
const reentryCalls=[{target:target.address,value:0,data:target.interface.encodeFunctionData('reenter',[wallet.address,inner])}];
await evm.send(wallet,'execute',[reentryCalls,deadline,await approvals(reentryCalls,4)]);
equal((await evm.call(target,'value'))[0],99n,'reentrancy blocked while outer call succeeds');
const otherWallet=await evm.deploy('PQWallet',[[hashV.address,mlV.address,falconV.address],owners,policy]);
await evm.send(otherWallet,'execute',[calls,deadline,firstApprovals],{revert:true});checks++;
await assert.rejects(evm.deploy('PQWallet',[[hashV.address,mlV.address,falconV.address],[owners[0],owners[0]],{threshold:2,hashMin:0,mlMin:0,falconMin:0}]));checks++;
const repeatedFalcon=await evm.deploy('KeyData',[falconExpanded.wire]);
await assert.rejects(evm.deploy('PQWallet',[[hashV.address,mlV.address,falconV.address],[owners[2],{key:pointer(repeatedFalcon.address),algorithm:3}],{threshold:2,hashMin:0,mlMin:0,falconMin:0}]));checks++;
const repeatedDescriptor=await evm.deploy('KeyData',[concat([mlPart0.address,mlPart1.address,mlExpanded.tr])]);
await assert.rejects(evm.deploy('PQWallet',[[hashV.address,mlV.address,falconV.address],[owners[1],{key:pointer(repeatedDescriptor.address),algorithm:2}],{threshold:2,hashMin:0,mlMin:0,falconMin:0}]));checks++;
const familyWallet=await evm.deploy('PQWallet',[[hashV.address,mlV.address,falconV.address],owners,{threshold:2,hashMin:0,mlMin:0,falconMin:1}]);
const familyDigest=(await evm.call(familyWallet,'digest',[calls,deadline]))[0];
const familyApprovals=[{owner:0,signature:signWotsAt(tree,familyDigest,5)},{owner:1,signature:hexlify(evmML.sign(getBytes(familyDigest),ml.secretKey,{extraEntropy:false}))}];
await evm.send(familyWallet,'execute',[calls,deadline,familyApprovals],{revert:true});checks++;
console.log('Mixed 3-of-3 wallet and negative cases pass');

// Write only compact measurements, never VM traces or secret test key material.
const compact=Object.fromEntries(Object.entries(bench).map(([name,r])=>[name,{transactionGas:r.gas,executionGas:r.execution}]));
const report={date:'2026-10-28',compiler:JSON.parse(fs.readFileSync('artifacts/build.json')).compiler,evm:'Prague (compiler targets Cancun)',optimizerRuns:1000000,checks,measurements:compact,deployments:{wallet:wallet.deploymentGas,hashVerifier:hashV.deploymentGas,mlVerifier:mlV.deploymentGas,falconVerifier:falconV.deploymentGas,mlKey:mlData.deploymentGas+mlPart0.deploymentGas+mlPart1.deploymentGas,baselineMLKey:baselineKey.deploymentGas,falconKey:falconData.deploymentGas},notes:['Local EthereumJS actual signed transactions; includes base gas, calldata and Prague calldata floor.','Custom schemes are experimental and not standard ML-DSA/Falcon.','Gas depends on signature values; these are single-vector samples, not worst-case bounds.','Key registration/deployment is separate from per-transaction verification.']};
fs.mkdirSync('benchmarks',{recursive:true});fs.writeFileSync('benchmarks/latest.json',JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify(report,null,2));
console.log(`PASS: ${checks} checks`);
