import { QubicVault } from '../src/vault';

describe('Vault', () => {
    describe('importAndUnlock', () => {
        it('should import and unlock a vault file successfully', async () => {
            const vault = new QubicVault();
            const password = 'mypassword';
            const file = new File(['encrypted data'], 'vault.dat');
            const result = await vault.importAndUnlock(true, password, null, file);
            expect(result).toBe(true);
            expect(vault.isWalletReady).toBe(true);
        });

        it('should fail to import and unlock with incorrect password', async () => {
            const vault = new QubicVault();
            const password = 'wrongpassword';
            const file = new File(['encrypted data'], 'vault.dat');
            await expect(vault.importAndUnlock(true, password, null, file)).rejects.toEqual('Import Failed (password or file do not match)');
            expect(vault.isWalletReady).toBe(false);
        });

        it('should fail to import and unlock with no file', async () => {
            const vault = new QubicVault();
            const password = 'mypassword';
            await expect(vault.importAndUnlock(true, password, null, null)).rejects.toEqual('Unlock Failed (no file)');
            expect(vault.isWalletReady).toBe(false);
        });

        it('should import a configuration file successfully', async () => {
            const vault = new QubicVault();
            const configData = JSON.stringify({ config: 'data' });
            const configFile = new File([configData], 'config.json');
            const result = await vault.importAndUnlock(false, '', configFile, null);
            expect(result).toBe(true);
        });

        it('should fail to import an invalid configuration file', async () => {
            const vault = new QubicVault();
            const invalidFile = new File(['invalid data'], 'invalid.txt');
            await expect(vault.importAndUnlock(false, '', invalidFile, null)).rejects.toEqual('Unlock Failed (no file)');
        });
    });
});
