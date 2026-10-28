import fs from 'node:fs';
import path from 'node:path';
import {makeWotsTree,signWotsAt} from './wots.mjs';
// State is secret. Do not place real key files in this repository or a synced folder.
const [command,file,arg,window]=process.argv.slice(2);
if(!file||!['keygen','sign'].includes(command))throw Error('Usage: node scripts/wots-cli.mjs keygen /secure/key.json [height] | sign /secure/key.json 0xDIGEST');
const lock=file+'.lock';let locked=false;
function durableWrite(file,data,exclusive=false) {
  const fd=fs.openSync(file,exclusive?'wx':'w',0o600);
  try{fs.writeFileSync(fd,JSON.stringify(data));fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
}
try{
  const fd=fs.openSync(lock,'wx',0o600);fs.closeSync(fd);locked=true;
  if(command==='keygen'){
    const tree=makeWotsTree(Number(arg??4),undefined,undefined,Number(window??8));durableWrite(file,tree,true);
    const dir=fs.openSync(path.dirname(path.resolve(file)),'r');try{fs.fsyncSync(dir);}finally{fs.closeSync(dir);}
    console.log(JSON.stringify({root:tree.root,height:tree.height,file}));
  }else{
    if(!/^0x[0-9a-fA-F]{64}$/.test(arg??''))throw Error('Expected bytes32 digest');
    const stat=fs.statSync(file);if((stat.mode&0o077)!==0)throw Error('Key state permissions must be 0600');
    const tree=JSON.parse(fs.readFileSync(file,'utf8')),leaf=tree.nextLeaf;
    if(![8,16].includes(tree.window)||tree.version!==`KWOTS${tree.window}-Merkle-v1`)throw Error('Unsupported WOTS key version');
    if(!Number.isInteger(leaf)||leaf<0||leaf>=2**tree.height)throw Error('Key exhausted');
    // Burn the leaf BEFORE computing or releasing a signature. A crash burns a leaf.
    tree.nextLeaf++;
    const tmp=file+'.pending';durableWrite(tmp,tree,true);fs.renameSync(tmp,file);
    const dir=fs.openSync(path.dirname(path.resolve(file)),'r');try{fs.fsyncSync(dir);}finally{fs.closeSync(dir);}
    console.log(signWotsAt(tree,arg,leaf));
  }
}finally{if(locked)fs.unlinkSync(lock);}
