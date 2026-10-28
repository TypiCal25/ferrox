import fs from 'node:fs';
import {createRequire} from 'node:module';
const require = createRequire(import.meta.url);
fs.mkdirSync('artifacts/signers', {recursive: true});
function source(name) {
  return fs.readFileSync(require.resolve('@noble/post-quantum/'+name+'.js'), 'utf8')
    .replaceAll('"./_crystals.js"', "'@noble/post-quantum/_crystals.js'")
    .replaceAll('"./utils.js"', "'@noble/post-quantum/utils.js'");
}
function once(s, old, replacement) {
  if (s.split(old).length !== 2) throw Error('Reference source drift: '+old);
  return s.replace(old, replacement);
}
let falcon = source('falcon');
let upstreamFalcon = once(falcon, 'const h = shake256.create().update(nonce).update(msg);',
  'const h = keccakCTR.create().update(nonce).update(msg);');
upstreamFalcon = "// GENERATED benchmark adapter for the pinned upstream ETHFalcon hash profile.\nimport {keccakCTR} from '../../scripts/keccak-ctr.mjs';\n" + upstreamFalcon;
fs.writeFileSync('artifacts/signers/falcon-upstream-evm.mjs', upstreamFalcon);
falcon = once(falcon, 'const h = shake256.create().update(nonce).update(msg);',
  "const h = keccakCTR.create().update(keccak_256(new TextEncoder().encode('PQWALLET/FALCON512/POINT32/v1'))).update(nonce).update(msg);");
falcon = once(falcon, 'const kQ = 5 * Q;', 'const kQ = Math.floor(2 ** 32 / Q) * Q;');
falcon = once(falcon, 'const tmp = h.xof(2);', 'const tmp = h.xof(4);');
falcon = once(falcon, 'let w = (tmp[0] << 8) | tmp[1];', 'let w = tmp[0] * 2 ** 24 + (tmp[1] << 16) + (tmp[2] << 8) + tmp[3];');
falcon = "// GENERATED experimental hash-to-point adaptation; original MIT notices follow.\nimport {keccakCTR} from '../../scripts/keccak-ctr.mjs';\nimport {keccak_256} from '@noble/hashes/sha3.js';\n" + falcon;
fs.writeFileSync('artifacts/signers/falcon-evm.mjs', falcon);
let ml = source('ml-dsa');
ml = once(ml, 'const s = shake256.create({}).update(seed);', 'const s = keccakCTR.create({}).update(seed);');
const mu = 'shake256.create({ dkLen: CRH_BYTES }).update(tr).update(msg).digest()';
if (ml.split(mu).length !== 3) throw Error('Reference mu source drift');
ml = ml.replaceAll(mu, mu.replace('shake256', 'keccakCTR'));
ml = once(ml, 'const cTilde = shake256\n', 'const cTilde = keccakCTR\n');
ml = once(ml, 'const c2 = shake256\n', 'const c2 = keccakCTR\n');
ml = "// GENERATED experimental ETHDilithium hash adaptation; original MIT notices follow.\nimport {keccakCTR} from '../../scripts/keccak-ctr.mjs';\n" + ml;
fs.writeFileSync('artifacts/signers/mldsa-evm.mjs', ml);
console.log('Generated experimental signers from pinned noble source; key generation and secret sampling unchanged.');
