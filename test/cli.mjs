import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import {execFileSync,spawn} from 'node:child_process';
import {id,getBytes} from 'ethers';
import {verifyWots} from '../scripts/wots.mjs';
import {ml_dsa44} from '../artifacts/signers/mldsa-evm.mjs';

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'pq-wallet-cli-'));
const run=(script,args)=>execFileSync(process.execPath,[script,...args],{encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
try {
  const file=path.join(dir,'state.key.json');
  const generated=JSON.parse(run('scripts/wots-cli.mjs',['keygen',file,'1']));
  assert.equal(fs.statSync(file).mode&0o777,0o600);
  const first=run('scripts/wots-cli.mjs',['sign',file,id('cli message 0')]);
  assert(verifyWots(generated.root,id('cli message 0'),first));
  assert.equal(JSON.parse(fs.readFileSync(file)).nextLeaf,1);
  // Concurrent processes must not produce two signatures from the remaining leaf.
  const child=digest=>new Promise(resolve=>{
    const p=spawn(process.execPath,['scripts/wots-cli.mjs','sign',file,digest]);let out='';
    p.stdout.on('data',b=>out+=b);p.stderr.resume();p.on('close',code=>resolve({code,out:out.trim(),digest}));
  });
  const raced=await Promise.all([child(id('race A')),child(id('race B'))]);
  assert.equal(raced.filter(r=>r.code===0).length,1);
  const winner=raced.find(r=>r.code===0);assert(verifyWots(generated.root,winner.digest,winner.out));
  assert.equal(JSON.parse(fs.readFileSync(file)).nextLeaf,2);
  assert.throws(()=>run('scripts/wots-cli.mjs',['sign',file,id('exhausted')]));
  fs.writeFileSync(file+'.lock','');
  assert.throws(()=>run('scripts/wots-cli.mjs',['sign',file,id('locked')]));
  fs.unlinkSync(file+'.lock');
  const keyFile=path.join(dir,'lattice.key.json');
  run('scripts/pq-cli.mjs',['keygen','mldsa44-keccak',keyFile]);
  assert.equal(fs.statSync(keyFile).mode&0o777,0o600);
  const key=JSON.parse(fs.readFileSync(keyFile));
  const signature=run('scripts/pq-cli.mjs',['sign',keyFile,id('CLI ML message')]);
  assert(ml_dsa44.verify(getBytes(signature),getBytes(id('CLI ML message')),getBytes(key.publicKey)));
  const pub=JSON.parse(fs.readFileSync(keyFile+'.public.json'));
  assert.equal(pub.parts.length,2);assert.equal(getBytes(pub.parts[0]).length,20480);assert.equal(getBytes(pub.parts[1]).length,20480);
  fs.chmodSync(keyFile,0o644);
  assert.throws(()=>run('scripts/pq-cli.mjs',['sign',keyFile,id('bad permissions')]));
  console.log('PASS: CLI key permissions, persistent leaf allocation, concurrent signing, exhaustion, and lattice signing');
} finally {fs.rmSync(dir,{recursive:true,force:true});}
