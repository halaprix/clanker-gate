/**
 * Interface-level tests for the three gate clients through stub viem clients.
 * The stubs capture the args each client emits so the shared base's behaviour
 * (guards, arg construction, permission encoding) is pinned once per client.
 */
import { describe, it, expect, vi } from 'vitest';
import type { PublicClient, WalletClient } from 'viem';
import type { Permission } from '../types/index.js';
import { OP } from '../types/index.js';
import { createClankerGate4337Client } from '../clients/ClankerGate4337Client.js';
import { createClankerGate7579Client } from '../clients/ClankerGate7579Client.js';
import { createClankerGateSafeClient } from '../clients/ClankerGateSafeClient.js';
import { toOnChainStruct } from '../clients/permission-codec.js';

const GATE = '0x00000000000000000000000000000000000000aa' as const;
const ACCOUNT = '0x00000000000000000000000000000000000000bb' as const;
const TARGET = '0x00000000000000000000000000000000000000cc' as const;
const ROOT = '0x1111111111111111111111111111111111111111111111111111111111111111' as const;

const permission: Permission = {
  target: TARGET,
  selector: '0xc04b8d59',
  rules: [
    {
      offset: 32,
      op: OP.LTE,
      value: '0x0000000000000000000000000000000000000000000000000de0b6b3a7640000',
    },
  ],
  chainId: 1,
};

function stubClients() {
  const readContract = vi.fn().mockResolvedValue('0xread');
  const writeContract = vi.fn().mockResolvedValue('0xtxhash');
  return {
    publicClient: { readContract } as unknown as PublicClient,
    walletClient: { writeContract } as unknown as WalletClient,
    readContract,
    writeContract,
  };
}

describe('gate clients through the shared base', () => {
  it('4337 setPolicyRoot writes with the account as target and signer', async () => {
    const { publicClient, walletClient, writeContract } = stubClients();
    const client = createClankerGate4337Client({ address: GATE, publicClient, walletClient });

    await client.setPolicyRoot({ account: ACCOUNT, root: ROOT });

    expect(writeContract).toHaveBeenCalledWith(
      expect.objectContaining({
        address: GATE,
        functionName: 'setPolicyRoot',
        args: [ACCOUNT, ROOT],
        account: ACCOUNT,
      })
    );
  });

  it('7579 setPolicyRoot writes with targetAccount as target and account as signer', async () => {
    const { publicClient, walletClient, writeContract } = stubClients();
    const client = createClankerGate7579Client({ address: GATE, publicClient, walletClient });

    await client.setPolicyRoot({ account: ACCOUNT, targetAccount: TARGET, root: ROOT });

    expect(writeContract).toHaveBeenCalledWith(
      expect.objectContaining({
        functionName: 'setPolicyRoot',
        args: [TARGET, ROOT],
        account: ACCOUNT,
      })
    );
  });

  it('Safe setPolicyRoot writes with the safe as target and account as signer', async () => {
    const { publicClient, walletClient, writeContract } = stubClients();
    const client = createClankerGateSafeClient({ address: GATE, publicClient, walletClient });

    await client.setPolicyRoot({ safe: TARGET, root: ROOT, account: ACCOUNT });

    expect(writeContract).toHaveBeenCalledWith(
      expect.objectContaining({
        functionName: 'setPolicyRoot',
        args: [TARGET, ROOT],
        account: ACCOUNT,
      })
    );
  });

  it('writes throw without a wallet client; reads still work', async () => {
    const { publicClient, readContract } = stubClients();
    const client = createClankerGate4337Client({ address: GATE, publicClient });

    expect(() => client.setPolicyRoot({ account: ACCOUNT, root: ROOT })).toThrow(
      'Wallet client required for write operations'
    );

    await client.getNonce(ACCOUNT);
    expect(readContract).toHaveBeenCalledWith(
      expect.objectContaining({ functionName: 'nonces', args: [ACCOUNT] })
    );
  });

  it('all three clients emit the identical codec struct for computePermissionHash', async () => {
    const expected = toOnChainStruct(permission);
    for (const create of [
      createClankerGate4337Client,
      createClankerGate7579Client,
      createClankerGateSafeClient,
    ]) {
      const { publicClient, readContract } = stubClients();
      const client = create({ address: GATE, publicClient });

      await client.computePermissionHash(ACCOUNT, permission, 7n);

      expect(readContract).toHaveBeenCalledWith(
        expect.objectContaining({
          functionName: 'computePermissionHash',
          args: [ACCOUNT, expected, 7n],
        })
      );
    }
  });

  it('Safe execTransaction passes the codec-encoded permission and proof', async () => {
    const { publicClient, walletClient, writeContract } = stubClients();
    const client = createClankerGateSafeClient({ address: GATE, publicClient, walletClient });

    await client.execTransaction({
      safe: TARGET,
      to: permission.target,
      value: 0n,
      data: '0x',
      operation: 0,
      proof: [ROOT],
      permission,
      account: ACCOUNT,
    });

    expect(writeContract).toHaveBeenCalledWith(
      expect.objectContaining({
        functionName: 'execTransaction',
        args: [TARGET, permission.target, 0n, '0x', 0, [ROOT], toOnChainStruct(permission)],
      })
    );
  });
});
