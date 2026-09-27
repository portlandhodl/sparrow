package com.sparrowwallet.sparrow.io;

import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.wallet.Wallet;

import java.io.OutputStream;

public interface WalletExport extends ImportExport {
    void exportWallet(Wallet wallet, OutputStream outputStream, String password) throws ExportException;
    String getWalletExportDescription();
    String getExportFileExtension(Wallet wallet);
    boolean isWalletExportScannable();
    boolean walletExportRequiresDecryption();
    default boolean isWalletExportFile() {
        return true;
    }
    default boolean exportsAllWallets() {
        return false;
    }

    default void checkStandardChildDerivation(Wallet wallet) throws ExportException {
        if(wallet.getKeystores().stream().anyMatch(keystore -> keystore.getChildDerivation() != null)) {
            throw new ExportException(getName() + " does not support wallets with non standard receive and change derivations.");
        }
    }

    default void checkSortedMultisig(Wallet wallet) throws ExportException {
        if(wallet.getPolicyType() == PolicyType.MULTI_HD && !wallet.isSortedMultisig()) {
            throw new ExportException(getName() + " does not support multi() wallets with keys in a fixed order, only BIP67 sortedmulti() wallets.");
        }
    }
}
