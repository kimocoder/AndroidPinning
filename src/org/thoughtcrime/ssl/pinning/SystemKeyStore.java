/**
 * Copyright (C) 2011-2013 Moxie Marlinspike
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.thoughtcrime.ssl.pinning;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;

import android.os.Build;

/**
 * An interface to the system's trust anchors. 
 * 
 * Modified to use system trust store file on pre-ICS and 
 * "AndroidCAStore" <code>KeyStore</code> on ICS+.
 *
 * @author Moxie Marlinspike
 */
public class SystemKeyStore {

    private static SystemKeyStore instance;

    public static synchronized SystemKeyStore getInstance() {
        if (instance == null) {
            instance = new SystemKeyStore();
        }
        return instance;
    }

    private final HashMap<Principal, X509Certificate> trustRoots;
    final KeyStore trustStore;

    private SystemKeyStore() {
        final KeyStore trustStore = getTrustStore();
        this.trustRoots = initializeTrustedRoots(trustStore);
        this.trustStore = trustStore;
    }

    public boolean isTrustRoot(X509Certificate certificate) {
        final X509Certificate trustRoot = trustRoots.get(certificate
                .getSubjectX500Principal());
        return trustRoot != null
                && trustRoot.getPublicKey().equals(certificate.getPublicKey());
    }

    public X509Certificate getTrustRootFor(X509Certificate certificate) {
        final X509Certificate trustRoot = trustRoots.get(certificate
                .getIssuerX500Principal());

        if (trustRoot == null) {
            return null;
        }

        if (trustRoot.getSubjectX500Principal().equals(
                certificate.getSubjectX500Principal())) {
            return null;
        }

        try {
            certificate.verify(trustRoot.getPublicKey());
        } catch (GeneralSecurityException e) {
            return null;
        }

        return trustRoot;
    }

    private HashMap<Principal, X509Certificate> initializeTrustedRoots(
            KeyStore trustStore) {
        try {
            final HashMap<Principal, X509Certificate> trusted = new HashMap<Principal, X509Certificate>();

            for (Enumeration<String> aliases = trustStore.aliases(); aliases
                    .hasMoreElements();) {
                final String alias = aliases.nextElement();
                final X509Certificate cert = (X509Certificate) trustStore
                        .getCertificate(alias);

                if (cert != null) {
                    trusted.put(cert.getSubjectX500Principal(), cert);
                }
            }

            return trusted;
        } catch (KeyStoreException e) {
            throw new AssertionError(e);
        }
    }

    private KeyStore getTrustStore() {
        try {
            KeyStore trustStore = null;

            if (Build.VERSION.SDK_INT >= 14) {
                trustStore = KeyStore.getInstance("AndroidCAStore");
                trustStore.load(null, null);
            } else {
                trustStore = KeyStore.getInstance("BKS");
                trustStore.load(new BufferedInputStream(new FileInputStream(
                        getTrustStorePath())), getTrustStorePassword()
                        .toCharArray());
            }

            return trustStore;
        } catch (NoSuchAlgorithmException nsae) {
            throw new AssertionError(nsae);
        } catch (KeyStoreException e) {
            throw new AssertionError(e);
        } catch (CertificateException e) {
            throw new AssertionError(e);
        } catch (FileNotFoundException e) {
            throw new AssertionError(e);
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    private String getTrustStorePath() {
        String path = System.getProperty("javax.net.ssl.trustStore");

        if (path == null) {
            path = System.getProperty("java.home") + File.separator + "etc"
                    + File.separator + "security" + File.separator
                    + "cacerts.bks";
        }

        return path;
    }

    private String getTrustStorePassword() {
        String password = System
                .getProperty("javax.net.ssl.trustStorePassword");

        if (password == null) {
            password = "changeit";
        }

        return password;
    }

}
