"""Generate a standalone LaTeX report from the recorded benchmark snapshot."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
data = json.loads((ROOT / 'benchmarks/latest.json').read_text())
measure = data['measurements']
deploy = data['deployments']
template = (HERE / 'report-template.tex').read_text()

def num(x):
    return f'{x:,}'

def reduction(a, b):
    return f'{100 * (1 - a / b):.1f}'

values = {
    'CHECKS': num(data['checks']),
    'BENCHSHA': hashlib.sha256((ROOT / 'benchmarks/latest.json').read_bytes()).hexdigest(),
    'MLTXRED': reduction(measure['mldsa']['transactionGas'], measure['mldsaUpstreamKeccak']['transactionGas']),
    'MLEXECRED': reduction(measure['mldsa']['executionGas'], measure['mldsaUpstreamKeccak']['executionGas']),
    'FALTXRED': reduction(measure['falcon']['transactionGas'], measure['falconUpstreamKeccak']['transactionGas']),
    'FALTXFACTOR': f"{measure['falconUpstreamKeccak']['transactionGas']/measure['falcon']['transactionGas']:.2f}",
    'WOTSTXRED': reduction(measure['wots']['transactionGas'], measure['wots16']['transactionGas']),
    'CHALLENGERED': reduction(measure['challengeOptimized']['executionGas'], measure['challengeReference']['executionGas']),
    'MATRIXRED': reduction(123549, 224704),
    'MLLATESTRED': reduction(measure['mldsa']['executionGas'], 847709),
    'FALLATESTRED': reduction(measure['falcon']['executionGas'], 447047),
    'KEYEXTRA': num(deploy['mlKey'] - deploy['baselineMLKey']),
    'MLTXSAVED': num(measure['mldsaUpstreamKeccak']['transactionGas'] - measure['mldsa']['transactionGas']),
}
for key, entry in measure.items():
    for field, value in entry.items():
        values[key.upper() + '_' + field.upper()] = num(value)
for key, value in deploy.items():
    values['DEPLOY_' + key.upper()] = num(value)
for name in ['PQWallet', 'KeccakWOTS', 'MLDSAKeccak', 'FalconKeccak']:
    artifact = json.loads((ROOT / 'artifacts' / (name + '.json')).read_text())
    values['SIZE_' + name.upper()] = num(len(artifact['evm']['deployedBytecode']['object']) // 2)
for key, value in values.items():
    template = template.replace('@@' + key + '@@', str(value))
if '@@' in template:
    raise ValueError('Unresolved report placeholder')
target = HERE / 'pq_multisig_report.tex'
target.write_text(template)
print(target)
