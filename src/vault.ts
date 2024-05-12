import { IConfig, IEncryptedVaultFile, IVaultFile } from '../model/config';

export class QubicVault {

    private runningConfiguration!: IConfig;
    private configName = '';
    public privateKey: CryptoKey | null = null;
    public publicKey: CryptoKey | null = null;
    public isWalletReady = false;

    private rsaAlg = {
        name: 'RSA-OAEP',
        modulusLength: 4096,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: 'SHA-256' },
    };

    private aesAlg = {
        name: 'AES-GCM',
        length: 256,
        iv: new Uint8Array(12).fill(0),
    };

    private encAlg = {
        name: 'RSA-OAEP',
    };


    public async importAndUnlock(
        selectedFileIsVaultFile: boolean,
        password: string,
        selectedConfigFile: File | null = null,
        file: File | null = null,
        unlock: boolean = false
    ): Promise<boolean> {
        if (selectedFileIsVaultFile) {
            // one vault file
            const binaryFileData = await file?.arrayBuffer();
            if (binaryFileData) {
                const success = await this.importVault(binaryFileData, (<any>password));
                if (success) {
                    this.isWalletReady = true;
                    return this.isWalletReady;
                } else {
                    return Promise.reject("Import Failed (password or file do not match)");
                }
            } else {
                return Promise.reject("Unlock Failed (no file)");
            }
        } else {
            const binaryFileData = await selectedConfigFile?.arrayBuffer();
            if (binaryFileData) {
                const enc = new TextDecoder("utf-8");
                const jsonData = enc.decode(binaryFileData);
                if (jsonData) {
                    const config = JSON.parse(jsonData);

                    // import configuration
                    if ((await unlock)) {
                        // legacy format
                        await this.importConfig(config);
                    }
                    return true;
                } else {
                    return Promise.reject("Unlock Failed (no file)");
                }
            }
            return false;
        }
    }



    private async importVault(
        binaryVaultFile: ArrayBuffer /* encrypted vault file */,
        password: string
    ): Promise<boolean> {
        if (!this.isVaultFile(binaryVaultFile))
            return Promise.reject('INVALID VAULT FILE');

        try {
            // unlock
            await this.unlockVault(binaryVaultFile, password);
            const vault = await this.convertBinaryVault(binaryVaultFile, password);

            // import configuration
            await this.importConfig(vault.configuration);
            return true;
        } catch (e) {
            return false;
        }
    }


    private isVaultFile(binaryFile: ArrayBuffer): boolean {
        try {
            const enc = new TextDecoder('utf-8');
            const jsonData = enc.decode(binaryFile);
            const vaultFile = JSON.parse(jsonData) as IEncryptedVaultFile;
            return (
                vaultFile !== undefined &&
                vaultFile.cipher !== undefined &&
                vaultFile.iv !== undefined &&
                vaultFile.salt !== undefined
            );
        } catch (error) {
            return false;
        }
    }


    private async unlockVault(
        binaryVaultFile: ArrayBuffer /* encrypted vault file */,
        password: string
    ): Promise<boolean> {
        if (!this.isVaultFile(binaryVaultFile))
            return Promise.reject('INVALID VAULT FILE');

        try {
            const decryptedVaultFile = await this.convertBinaryVault(
                binaryVaultFile,
                password
            );
            const privKey = this.base64ToArrayBuffer(decryptedVaultFile.privateKey);
            const { privateKey, publicKey } = await this.importEncryptedPrivateKey(
                privKey,
                password
            );

            await this.setKeys(publicKey, privateKey);
            await this.save();
            return true;
        } catch (error) {
            return Promise.reject(error);
        }
    }


    private async save(lock: boolean = false): Promise<void> {
        await this.saveConfig(lock);
    }


    private async saveConfig(lock: boolean) {
        if (lock) {
            // when locking we don't want that the public key is saved.
            this.runningConfiguration.publicKey = undefined;
            localStorage.setItem(
                this.configName,
                JSON.stringify(this.runningConfiguration)
            );
        } else {
            try {
                const jwk = await crypto.subtle.exportKey('jwk', this.publicKey!);
                this.runningConfiguration.publicKey = jwk;
                localStorage.setItem(
                    this.configName,
                    JSON.stringify(this.runningConfiguration)
                );
            } catch (e) {
                // ignore
            }
        }
    }


    private async setKeys(
        publicKey: CryptoKey,
        privateKey: CryptoKey | null = null
    ) {
        this.publicKey = publicKey;
        // also push the current publickey to the running configuration
        const jwk = await crypto.subtle.exportKey('jwk', this.publicKey!);
        this.runningConfiguration.publicKey = jwk;

        if (privateKey) this.privateKey = privateKey;
    }


    /**
    * converts the binary vault file to the internal vault file format (uploaded by the user)
    * @param binaryVaultFile
    * @param password
    * @returns
    */
    private async convertBinaryVault(
        binaryVaultFile: ArrayBuffer /* encrypted vault file */,
        password: string
    ): Promise<IVaultFile> {
        try {
            const enc = new TextDecoder('utf-8');
            const encryptedVaultFile = JSON.parse(
                enc.decode(binaryVaultFile)
            ) as IEncryptedVaultFile;

            const decryptedVaultFile = await this.decryptVault(
                encryptedVaultFile,
                password
            );
            return decryptedVaultFile;
        } catch (error) {
            return Promise.reject(error);
        }
    }


    private async decryptVault(
        encryptedData: IEncryptedVaultFile,
        password: string
    ): Promise<IVaultFile> {
        const salt = this.base64ToBytes(encryptedData.salt);

        const key = await this.getVaultFileKey(password, salt);

        const iv = this.base64ToBytes(encryptedData.iv);

        const cipher = this.base64ToBytes(encryptedData.cipher);

        const contentBytes = new Uint8Array(
            await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipher)
        );
        const decryptedVault = this.bytesToString(contentBytes);
        return JSON.parse(decryptedVault);
    }


    private async importConfig(config: IConfig): Promise<boolean> {
        if (!config || config.seeds.length <= 0) return false;

        await this.loadConfig(config);
        await this.saveConfig(false);
        return true;
    }


    private async loadConfig(config: IConfig) {
        this.runningConfiguration = config;

        // convert json key to internal cryptokey
        if (this.runningConfiguration.publicKey) {
            const k = await crypto.subtle.importKey(
                'jwk',
                this.runningConfiguration.publicKey,
                this.rsaAlg,
                true,
                ['encrypt']
            );
            this.publicKey = k;
            this.isWalletReady = true;
        }
    }


    private async getVaultFileKey(password: string, salt: any) {
        const passwordBytes = this.stringToBytes(password);
        const initialKey = await crypto.subtle.importKey(
            'raw',
            passwordBytes,
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );

        return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
            initialKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }


    private async importEncryptedPrivateKey(
        wrappedKey: ArrayBuffer,
        password: string
    ): Promise<{ privateKey: CryptoKey; publicKey: CryptoKey }> {
        return this.importKey(password).then((pwKey: CryptoKey) => {
            return this.deriveKey(pwKey).then((wrapKey: CryptoKey) => {
                return crypto.subtle
                    .unwrapKey(
                        'jwk',
                        wrappedKey,
                        wrapKey,
                        this.aesAlg,
                        this.rsaAlg,
                        true,
                        ['decrypt']
                    )
                    .then((privateKey) => {
                        return this.getPublicKey(privateKey).then((publicKey) => {
                            return { privateKey, publicKey };
                        });
                    });
            });
        });
    }


    private async importKey(password: string) {
        const enc = new TextEncoder();
        const pw = enc.encode(password);

        return (<any>crypto.subtle).importKey(
            'raw',
            pw,
            { name: 'PBKDF2' },
            false,
            ['deriveBits', 'deriveKey']
        );
    }


    private async deriveKey(pwKey: CryptoKey) {
        const salt = new Uint8Array(16).fill(0);

        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt,
                iterations: 100000,
                hash: 'SHA-256',
            },
            pwKey,
            this.aesAlg,
            true,
            ['wrapKey', 'unwrapKey']
        );
    }


    private bytesToString(bytes: Uint8Array): string {
        return new TextDecoder().decode(bytes);
    }


    private stringToBytes(str: string): Uint8Array {
        return new TextEncoder().encode(str);
    }


    privatebytesToBase64(arr: Uint8Array): string {
        return btoa(Array.from(arr, (b) => String.fromCharCode(b)).join(''));
    }


    private base64ToBytes(base64: string): Uint8Array {
        return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
    }


    async getPublicKey(privateKey: CryptoKey) {
        const jwkPrivate = await crypto.subtle.exportKey('jwk', privateKey);
        delete jwkPrivate.d;
        jwkPrivate.key_ops = ['encrypt'];
        return crypto.subtle.importKey('jwk', jwkPrivate, this.rsaAlg, true, [
            'encrypt',
        ]);
    }

    private base64ToArrayBuffer(base64: string) {
        const binary_string = atob(base64);
        const len = binary_string.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binary_string.charCodeAt(i);
        }
        return bytes.buffer;
    }
}

