import fs from 'node:fs';
import {createHash} from 'node:crypto';
const build=JSON.parse(fs.readFileSync('artifacts/build.json'));
if(!build.sources)throw Error('Rebuild required: npm run build');
for(const [file,hash] of Object.entries(build.sources)) {
  if(createHash('sha256').update(fs.readFileSync(file)).digest('hex')!==hash)throw Error('Stale compiled source: '+file+'; run npm run build');
}
console.log('Compiled Solidity source hashes match');
