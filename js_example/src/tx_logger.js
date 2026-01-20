const LOG_TX = '🧾';
const LOG_WARN = '⚠️';
const LOG_EVENT = '📣';

export function logReceipt(result) {
  console.log(`${LOG_TX} Extrinsic hash: ${result.txHash.toHex()}`);
  if (result.status?.isInBlock) {
    console.log(`${LOG_TX} Block hash: ${result.status.asInBlock.toHex()}`);
  }
  if (result.status?.isFinalized) {
    console.log(`${LOG_TX} Finalized hash: ${result.status.asFinalized.toHex()}`);
  }
  const success = result.dispatchError == null;
  console.log(`${LOG_TX} Success: ${success}`);
  if (!success) {
    console.log(`${LOG_WARN} Error: ${result.dispatchError.toString()}`);
  }
  result.events.forEach(({ event }) => {
    console.log(`${LOG_EVENT} Event: ${event.section}.${event.method} ${event.data}`);
  });
}
