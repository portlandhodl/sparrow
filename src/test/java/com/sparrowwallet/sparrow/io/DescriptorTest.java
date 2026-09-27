package com.sparrowwallet.sparrow.io;

import com.sparrowwallet.drongo.ExtendedKey;
import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.OutputDescriptor;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.wallet.Keystore;
import com.sparrowwallet.drongo.wallet.Wallet;
import com.sparrowwallet.drongo.wallet.WalletNode;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.List;

public class DescriptorTest extends IoTest {
    @Test
    public void testImport() throws ImportException {
        Descriptor descriptor = new Descriptor();
        Wallet wallet = descriptor.importWallet(getInputStream("descriptor-receive.txt"), null);

        Assertions.assertEquals(ScriptType.P2WPKH, wallet.getScriptType());
        Keystore keystore = wallet.getKeystores().getFirst();
        Assertions.assertEquals("m/84'/0'/0'", keystore.getKeyDerivation().getDerivationPath());
        Assertions.assertEquals("a262308d", keystore.getKeyDerivation().getMasterFingerprint());
        Assertions.assertEquals(ExtendedKey.fromDescriptor("xpub6DM7CYgaTMdMbhTcLTUWmNUE5WLXK5hx8ZMa4sRw8qYJPqtqKYiKnwsmT8A6AijDVAUZRivdBnXdR8QE7Y9vVnqvzPL3fXCmu1WtCRLdAoz"), keystore.getExtendedPublicKey());
        Assertions.assertTrue(keystore.isValid());
    }

    @Test
    public void testImportMultipath() throws ImportException {
        Descriptor descriptor = new Descriptor();
        Wallet wallet = descriptor.importWallet(getInputStream("descriptor-multipath.txt"), null);

        Assertions.assertEquals(ScriptType.P2WPKH, wallet.getScriptType());
        Keystore keystore = wallet.getKeystores().getFirst();
        Assertions.assertEquals("m/84'/0'/0'", keystore.getKeyDerivation().getDerivationPath());
        Assertions.assertEquals("a262308d", keystore.getKeyDerivation().getMasterFingerprint());
        Assertions.assertEquals(ExtendedKey.fromDescriptor("xpub6DM7CYgaTMdMbhTcLTUWmNUE5WLXK5hx8ZMa4sRw8qYJPqtqKYiKnwsmT8A6AijDVAUZRivdBnXdR8QE7Y9vVnqvzPL3fXCmu1WtCRLdAoz"), keystore.getExtendedPublicKey());
        Assertions.assertTrue(keystore.isValid());
    }

    @Test
    public void testImportSeparateDescriptors() throws ImportException {
        Descriptor descriptor = new Descriptor();
        Wallet wallet = descriptor.importWallet(getInputStream("descriptor-receive-change1.txt"), null);

        Assertions.assertEquals(ScriptType.P2WPKH, wallet.getScriptType());
        Keystore keystore = wallet.getKeystores().getFirst();
        Assertions.assertEquals("m/84'/0'/0'", keystore.getKeyDerivation().getDerivationPath());
        Assertions.assertEquals("a262308d", keystore.getKeyDerivation().getMasterFingerprint());
        Assertions.assertEquals(ExtendedKey.fromDescriptor("xpub6DM7CYgaTMdMbhTcLTUWmNUE5WLXK5hx8ZMa4sRw8qYJPqtqKYiKnwsmT8A6AijDVAUZRivdBnXdR8QE7Y9vVnqvzPL3fXCmu1WtCRLdAoz"), keystore.getExtendedPublicKey());
        Assertions.assertTrue(keystore.isValid());
    }

    @Test
    public void testExport() throws ImportException, ExportException {
        Descriptor descriptor = new Descriptor();
        Wallet wallet = descriptor.importWallet(getInputStream("descriptor-multipath.txt"), null);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        descriptor.exportWallet(wallet, baos, null);
        String export = baos.toString();

        Assertions.assertTrue(export.contains("wpkh([a262308d/84h/0h/0h]xpub6DM7CYgaTMdMbhTcLTUWmNUE5WLXK5hx8ZMa4sRw8qYJPqtqKYiKnwsmT8A6AijDVAUZRivdBnXdR8QE7Y9vVnqvzPL3fXCmu1WtCRLdAoz/<0;1>/*)#cpx4ean7"));
        Assertions.assertTrue(export.contains("wpkh([a262308d/84h/0h/0h]xpub6DM7CYgaTMdMbhTcLTUWmNUE5WLXK5hx8ZMa4sRw8qYJPqtqKYiKnwsmT8A6AijDVAUZRivdBnXdR8QE7Y9vVnqvzPL3fXCmu1WtCRLdAoz/0/*)#s5x06kda"));
        Assertions.assertTrue(export.contains("wpkh([a262308d/84h/0h/0h]xpub6DM7CYgaTMdMbhTcLTUWmNUE5WLXK5hx8ZMa4sRw8qYJPqtqKYiKnwsmT8A6AijDVAUZRivdBnXdR8QE7Y9vVnqvzPL3fXCmu1WtCRLdAoz/1/*)#pqrw8ra9"));
    }

    @Test
    public void testImportExport() throws ImportException, ExportException {
        Descriptor descriptor = new Descriptor();
        Wallet wallet = descriptor.importWallet(getInputStream("descriptor-multipath.txt"), null);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        descriptor.exportWallet(wallet, baos, null);

        Wallet reimported = descriptor.importWallet(new ByteArrayInputStream(baos.toByteArray()), null);

        Assertions.assertEquals(wallet.getScriptType(), reimported.getScriptType());
        Keystore keystore = wallet.getKeystores().getFirst();
        Keystore reimportedKeystore = reimported.getKeystores().getFirst();
        Assertions.assertEquals(keystore.getKeyDerivation().getDerivationPath(), reimportedKeystore.getKeyDerivation().getDerivationPath());
        Assertions.assertEquals(keystore.getKeyDerivation().getMasterFingerprint(), reimportedKeystore.getKeyDerivation().getMasterFingerprint());
        Assertions.assertEquals(keystore.getExtendedPublicKey(), reimportedKeystore.getExtendedPublicKey());
        Assertions.assertTrue(reimportedKeystore.isValid());
    }

    @Test
    public void testImportLabelled() throws ImportException {
        Descriptor descriptor = new Descriptor();
        Wallet wallet = descriptor.importWallet(getInputStream("descriptor-labelled.txt"), null);

        Assertions.assertEquals(ScriptType.P2WPKH, wallet.getScriptType());
        Keystore keystore = wallet.getKeystores().getFirst();
        Assertions.assertEquals("m/84'/0'/0'", keystore.getKeyDerivation().getDerivationPath());
        Assertions.assertEquals("a262308d", keystore.getKeyDerivation().getMasterFingerprint());
        Assertions.assertEquals(ExtendedKey.fromDescriptor("xpub6DM7CYgaTMdMbhTcLTUWmNUE5WLXK5hx8ZMa4sRw8qYJPqtqKYiKnwsmT8A6AijDVAUZRivdBnXdR8QE7Y9vVnqvzPL3fXCmu1WtCRLdAoz"), keystore.getExtendedPublicKey());
        Assertions.assertTrue(keystore.isValid());
    }

    @Test
    public void testImportSeparateDescriptorsNoBlankLine() throws ImportException {
        Descriptor descriptor = new Descriptor();
        Wallet wallet = descriptor.importWallet(getInputStream("descriptor-receive-change2.txt"), null);

        Assertions.assertEquals(ScriptType.P2WPKH, wallet.getScriptType());
        Keystore keystore = wallet.getKeystores().getFirst();
        Assertions.assertEquals("m/84'/0'/0'", keystore.getKeyDerivation().getDerivationPath());
        Assertions.assertEquals("a262308d", keystore.getKeyDerivation().getMasterFingerprint());
        Assertions.assertEquals(ExtendedKey.fromDescriptor("xpub6DM7CYgaTMdMbhTcLTUWmNUE5WLXK5hx8ZMa4sRw8qYJPqtqKYiKnwsmT8A6AijDVAUZRivdBnXdR8QE7Y9vVnqvzPL3fXCmu1WtCRLdAoz"), keystore.getExtendedPublicKey());
        Assertions.assertTrue(keystore.isValid());
    }

    private static final String CUSTOM_CHAIN_DESCRIPTOR = "wsh(multi(2,[00000004/0/0/0/0]xpub6ESApoTBCctw7rBf6A2kKaMekdtXQ9SS1MmWxYCZEUcjRptReaFvi1NXCaUhiSNCzaxeMzzh1S6sMud4ihHnv46jjF8nFnrAmpX6pdRsAd6/0/0/<20;21>/*," +
            "[00000003/0/0/0/0]xpub6EWeDK8fGBHhUgb5udr7kmdsgxPd613AQGh2ZPvmDtrSdU3Hyqr3yGaozpTDhHexCczjt8maQpS68aqxL1bduwh6UDf8zPayLRLZCpaVdzr/0/0/<20;21>/*," +
            "[00000005/0/0/0/0]xpub6D7FUuTvP5SN6YyyVriZwjLWCDDKkkoDdJ18DkU4rivAxW9n9Sz8iPC79h1UmZBhNTdNQEW67mLFQQKAHsUB8fTRkQ2W6FZKdsq1gkUdjWd/0/0/<20;21>/*))";

    @Test
    public void testUnsortedMultisigCustomChainsExport() throws ExportException, ImportException {
        Wallet wallet = OutputDescriptor.getOutputDescriptor(CUSTOM_CHAIN_DESCRIPTOR).toWallet();
        Descriptor descriptor = new Descriptor();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        descriptor.exportWallet(wallet, baos, null);
        String export = baos.toString();
        Assertions.assertTrue(export.contains("wsh(multi(2,"));
        Assertions.assertTrue(export.contains("/<20;21>/*"));

        Wallet reimported = descriptor.importWallet(new ByteArrayInputStream(baos.toByteArray()), null);
        Assertions.assertFalse(reimported.isSortedMultisig());
        Assertions.assertEquals("bc1qejjpms4tvwdtqp0kgc95kvf2s8n233meytrpal6xcvlqekqc90hq9s3p4h", new WalletNode(reimported, KeyPurpose.RECEIVE, 0).getAddress().toString());
        Assertions.assertEquals("bc1qz2e3lrey4232pk6upr4fwn68uef5nu84u5ljy8n90acg3vxles3q0denk0", new WalletNode(reimported, KeyPurpose.CHANGE, 0).getAddress().toString());

        //Formats that assume sortedmulti() and the /0/* and /1/* chains must refuse rather than export a wallet with different addresses
        for(WalletExport walletExport : List.of(new ColdcardMultisig(), new Electrum(), new CaravanMultisig(), new ElectrumPersonalServer(), new JadeMultisig())) {
            Assertions.assertThrows(ExportException.class, () -> walletExport.exportWallet(wallet, new ByteArrayOutputStream(), null), walletExport.getName());
        }
        for(WalletExport walletExport : List.of(new SpecterDesktop(), new SpecterDIY(), new Bip129())) {
            ExportException e = Assertions.assertThrows(ExportException.class, () -> walletExport.exportWallet(wallet, new ByteArrayOutputStream(), null), walletExport.getName());
            Assertions.assertTrue(e.getMessage().contains("receive and change"), walletExport.getName());
        }
    }
}
