import fs from 'node:fs';
import assert from 'node:assert/strict';
import {Common, Mainnet, Hardfork} from '@ethereumjs/common';
import {createBlock} from '@ethereumjs/block';
import {createVM, runTx} from '@ethereumjs/vm';
import {createLegacyTx} from '@ethereumjs/tx';
import {Account, createAddressFromPrivateKey, createAddressFromString, hexToBytes, bytesToHex} from '@ethereumjs/util';
import {Interface, ContractFactory} from 'ethers';

export const artifact=name=>JSON.parse(fs.readFileSync('artifacts/'+name+'.json'));
export async function createEVM() {
  const common=new Common({chain:Mainnet,hardfork:Hardfork.Prague});
  const vm=await createVM({common});
  const block=createBlock({header:{timestamp:1793145600n,gasLimit:30_000_000n,baseFeePerGas:7n}},{common});
  const privateKey=hexToBytes('0x'+'01'.repeat(32));
  const sender=createAddressFromPrivateKey(privateKey);
  await vm.stateManager.putAccount(sender,new Account(0n,10n**27n));
  async function tx(to,data='0x',value=0n,expectRevert=false) {
    const nonce=(await vm.stateManager.getAccount(sender)).nonce;
    const t=createLegacyTx({nonce,gasLimit:30_000_000n,gasPrice:10n**9n,...(to?{to}:{}),data,value},{common}).sign(privateKey);
    const result=await runTx(vm,{tx:t,block});
    const exception=result.execResult.exceptionError;
    if(expectRevert)assert(exception,'Expected transaction to revert');
    else if(exception)throw Error(exception.error+' '+bytesToHex(result.execResult.returnValue));
    return {gas:Number(result.totalGasSpent),execution:Number(result.execResult.executionGasUsed),output:bytesToHex(result.execResult.returnValue),address:result.createdAddress?.toString(),result};
  }
  async function deploy(name,args=[],value=0n) {
    const a=artifact(name),f=new ContractFactory(a.abi,'0x'+a.evm.bytecode.object);
    const r=await tx(null,(await f.getDeployTransaction(...args)).data,value);
    return {name,address:r.address,interface:new Interface(a.abi),deploymentGas:r.gas};
  }
  async function call(c,name,args=[]) {
    // Each static read has a fresh access list, independent of previous calls.
    await vm.evm.journal.cleanup();
    await vm.stateManager.checkpoint();
    try {
      const r=await vm.evm.runCall({block,caller:sender,to:createAddressFromString(c.address),data:hexToBytes(c.interface.encodeFunctionData(name,args)),gasLimit:30_000_000n,isStatic:true});
      if(r.execResult.exceptionError)throw Error(r.execResult.exceptionError.error+' '+bytesToHex(r.execResult.returnValue));
      return c.interface.decodeFunctionResult(name,bytesToHex(r.execResult.returnValue));
    } finally { await vm.stateManager.revert(); }
  }
  async function send(c,name,args=[],opts={}){return tx(c.address,c.interface.encodeFunctionData(name,args),opts.value??0n,opts.revert??false);}
  return {vm,common,sender,tx,deploy,call,send};
}
