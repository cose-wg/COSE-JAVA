/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import java.security.Provider;
import java.security.Security;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.AfterClass;
import org.junit.BeforeClass;

/**
 *
 * @author linuxwolf
 */
public abstract class TestBase {
    private static final Provider    PROVIDER = new BouncyCastleProvider();
    private static final Provider    EdDSA = new EdDSASecurityProvider();

    @BeforeClass
    public static void installProvider() throws Exception {
        Security.insertProviderAt(PROVIDER, 1);
        Security.insertProviderAt(EdDSA, 0);
    }
    @AfterClass
    public static void uninstallProvider() throws Exception {
        Security.removeProvider(PROVIDER.getName());
        Security.removeProvider(EdDSA.getName());
    }
}
