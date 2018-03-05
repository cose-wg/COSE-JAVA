/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

import java.security.Provider;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.AfterClass;
import org.junit.BeforeClass;

/**
 *
 * @author linuxwolf
 */
public abstract class TestBase {
    private static final Provider    PROVIDER = new BouncyCastleProvider();

    @BeforeClass
    public static void installProvider() throws Exception {
        Security.insertProviderAt(PROVIDER, 1);
    }
    @AfterClass
    public static void uninstallProvider() throws Exception {
        Security.removeProvider(PROVIDER.getName());
    }
}
