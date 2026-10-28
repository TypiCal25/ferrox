import fs from 'node:fs';
import path from 'node:path';
import solc from 'solc';
import {createHash} from 'node:crypto';

const entries = [
  'src/PQWallet.sol', 'src/KeyData.sol', 'src/KeccakWOTS.sol',
  'src/FalconKeccak.sol', 'src/MLDSAKeccak.sol', 'test/Harness.sol', 'test/KeccakWOTS16.sol',
  'vendor/ethfalcon/src/ZKNOX_falcon8.sol',
  'vendor/ethfalcon/src/ZKNOX_ethfalcon.sol',
  'vendor/ethdilithium/src/ZKNOX_ethdilithium.sol',
  'vendor/ethdilithium/src/ZKNOX_dilithium.sol',
];
const sources = Object.fromEntries(entries.map(p => [p, {content: fs.readFileSync(p, 'utf8')}]));
const hashes=Object.fromEntries(Object.entries(sources).map(([p,s])=>[p,createHash('sha256').update(s.content).digest('hex')]));
const input = {
  language: 'Solidity', sources,
  settings: {
    optimizer: {enabled: true, runs: 1_000_000}, viaIR: true, evmVersion: 'cancun',
    remappings: ['sstore2/=vendor/compat/', 'InterfaceVerifier/=vendor/compat/'],
    outputSelection: {'*': {'*': ['abi', 'evm.bytecode.object', 'evm.deployedBytecode.object']}}
  }
};
console.log('Compiling with', solc.version(), '(Cancun, viaIR, 1,000,000 optimizer runs)');
const output = JSON.parse(solc.compile(JSON.stringify(input), {import(p) {
  try {const contents=fs.readFileSync(p, 'utf8');hashes[p]=createHash('sha256').update(contents).digest('hex');return {contents};} catch {return {error: 'Missing import: '+p};}
}}));
for (const e of output.errors ?? []) if (e.severity === 'error') console.error(e.formattedMessage);
if ((output.errors ?? []).some(e => e.severity === 'error')) process.exit(1);
fs.mkdirSync('artifacts', {recursive: true});
let tooLarge = false;
for (const [file, contracts] of Object.entries(output.contracts)) {
  for (const [name, c] of Object.entries(contracts)) {
    if (!c.evm.bytecode.object) continue;
    const size = c.evm.deployedBytecode.object.length / 2;
    if (size > 24576) { console.error(name, 'exceeds EIP-170:', size); tooLarge = true; }
    fs.writeFileSync(path.join('artifacts', name+'.json'), JSON.stringify({file, name, ...c}, null, 2));
    console.log(name.padEnd(25), String(size).padStart(6), 'runtime bytes');
  }
}
fs.writeFileSync('artifacts/build.json', JSON.stringify({compiler: solc.version(), settings: input.settings, sources: hashes}, null, 2));
if (tooLarge) process.exit(1);
