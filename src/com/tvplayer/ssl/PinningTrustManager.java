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

package com.tvplayer.ssl;

import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import android.util.Log;

/**
 * A TrustManager implementation that enforces Certificate "pins."
 * 
 * <p>
 * PinningTrustManager is layered on top of the system's default TrustManager, such that the system continues to
 * validate CA signatures for SSL connections as usual. Additionally, however, PinningTrustManager will enforce
 * certificate constraints on the validated certificate chain. Specifically, it will ensure that one of an arbitrary
 * number of specified SubjectPublicKeyInfos appears somewhere in the valid certificate chain.
 * </p>
 * <p>
 * To use:
 * 
 * <pre>
 * TrustManager[] trustManagers = new TrustManager[1];
 * trustManagers[0] = new PinningTrustManager(SystemKeyStore.getInstance(), new String[] {
 * 	&quot;f30012bbc18c231ac1a44b788e410ce754182513&quot;
 * }, 0);
 * 
 * SSLContext sslContext = SSLContext.getInstance(&quot;TLS&quot;);
 * sslContext.init(null, trustManagers, null);
 * 
 * HttpsURLConnection urlConnection = (HttpsURLConnection) new URL(&quot;https://encrypted.google.com/&quot;).openConnection();
 * urlConnection.setSSLSocketFactory(sslContext.getSocketFactory());
 * InputStream in = urlConnection.getInputStream();
 * </pre>
 * 
 * </p>
 * 
 * @author Moxie Marlinspike
 */
public class PinningTrustManager implements X509TrustManager {

	private final TrustManager[] systemTrustManagers;
	private final SystemKeyStore systemKeyStore;
	private final long enforceUntilTimestampMillis;

	private final List<byte[]> pins = new LinkedList<byte[]>();
	private final Set<X509Certificate> cache = Collections.synchronizedSet(new HashSet<X509Certificate>());

	/**
	 * Constructs a PinningTrustManager with a set of valid pins.
	 * 
	 * @param keyStore
	 *            A SystemKeyStore that validation will be based on.
	 * 
	 * @param pins
	 *            An array of encoded pins to match a seen certificate chain against. A pin is a hex-encoded hash of a
	 *            X.509 certificate's SubjectPublicKeyInfo. A pin can be generated using the provided pin.py script:
	 *            python ./tools/pin.py certificate_file.pem
	 * 
	 * @param enforceUntilTimestampMillis
	 *            A timestamp (in milliseconds) when pins will stop being enforced. Normal non-pinned certificate
	 *            validation will continue. Set this to some period after your build date, or to 0 to enforce pins
	 *            forever.
	 */
	public PinningTrustManager(SystemKeyStore keyStore, String[] pins, long enforceUntilTimestampMillis) {
		this.systemTrustManagers = initializeSystemTrustManagers(keyStore);
		this.systemKeyStore = keyStore;
		this.enforceUntilTimestampMillis = enforceUntilTimestampMillis;

		for (String pin : pins) {
			this.pins.add(hexStringToByteArray(pin));
		}
	}

	private TrustManager[] initializeSystemTrustManagers(SystemKeyStore keyStore) {
		try {
			final TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509");
			tmf.init(keyStore.trustStore);

			return tmf.getTrustManagers();
		} catch (NoSuchAlgorithmException nsae) {
			throw new AssertionError(nsae);
		} catch (KeyStoreException e) {
			throw new AssertionError(e);
		}
	}

	private boolean isValidPin(X509Certificate certificate) throws CertificateException {
		try {
			final MessageDigest digest = MessageDigest.getInstance("SHA1");
			final byte[] spki = certificate.getPublicKey().getEncoded();
			final byte[] pin = digest.digest(spki);

			for (byte[] validPin : this.pins) {
				if (Arrays.equals(validPin, pin)) {
					return true;
				}
			}

			return false;
		} catch (NoSuchAlgorithmException nsae) {
			throw new CertificateException(nsae);
		}
	}

	private void checkSystemTrust(X509Certificate[] chain, String authType) throws CertificateException {
		for (TrustManager systemTrustManager : systemTrustManagers) {
			((X509TrustManager) systemTrustManager).checkServerTrusted(chain, authType);
		}
	}

	private void checkPinTrust(X509Certificate[] chain) throws CertificateException {

		if (enforceUntilTimestampMillis != 0 && System.currentTimeMillis() > enforceUntilTimestampMillis) {
			Log.w("PinningTrustManager", "Certificate pins are stale, falling back to system trust.");
			return;
		}

		final X509Certificate[] cleanChain = CertificateChainCleaner.getCleanChain(chain, systemKeyStore);

		for (X509Certificate certificate : cleanChain) {
			if (isValidPin(certificate)) {
				return;
			}
		}

		throw new CertificateException("No valid pins found in chain!");
	}

	public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		throw new CertificateException("Client certificates not supported!");
	}

	public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		if (cache.contains(chain[0])) {
			return;
		}

		// Note: We do this so that we'll never be doing worse than the default
		// system validation. It's duplicate work, however, and can be factored
		// out if we make the verification below more complete.
		checkSystemTrust(chain, authType);
		checkPinTrust(chain);
		cache.add(chain[0]);
	}

	private static final String EQUIFAX_ROOT = "-----BEGIN CERTIFICATE-----\n"
			+ "MIIDIDCCAomgAwIBAgIENd70zzANBgkqhkiG9w0BAQUFADBOMQswCQYDVQQGEwJV\n"
			+ "UzEQMA4GA1UEChMHRXF1aWZheDEtMCsGA1UECxMkRXF1aWZheCBTZWN1cmUgQ2Vy\n"
			+ "dGlmaWNhdGUgQXV0aG9yaXR5MB4XDTk4MDgyMjE2NDE1MVoXDTE4MDgyMjE2NDE1\n"
			+ "MVowTjELMAkGA1UEBhMCVVMxEDAOBgNVBAoTB0VxdWlmYXgxLTArBgNVBAsTJEVx\n"
			+ "dWlmYXggU2VjdXJlIENlcnRpZmljYXRlIEF1dGhvcml0eTCBnzANBgkqhkiG9w0B\n"
			+ "AQEFAAOBjQAwgYkCgYEAwV2xWGcIYu6gmi0fCG2RFGiYCh7+2gRvE4RiIcPRfM6f\n"
			+ "BeC4AfBONOziipUEZKzxa1NfBbPLZ4C/QgKO/t0BCezhABRP/PvwDN1Dulsr4R+A\n"
			+ "cJkVV5MW8Q+XarfCaCMczE1ZMKxRHjuvK9buY0V7xdlfUNLjUA86iOe/FP3gx7kC\n"
			+ "AwEAAaOCAQkwggEFMHAGA1UdHwRpMGcwZaBjoGGkXzBdMQswCQYDVQQGEwJVUzEQ\n"
			+ "MA4GA1UEChMHRXF1aWZheDEtMCsGA1UECxMkRXF1aWZheCBTZWN1cmUgQ2VydGlm\n"
			+ "aWNhdGUgQXV0aG9yaXR5MQ0wCwYDVQQDEwRDUkwxMBoGA1UdEAQTMBGBDzIwMTgw\n"
			+ "ODIyMTY0MTUxWjALBgNVHQ8EBAMCAQYwHwYDVR0jBBgwFoAUSOZo+SvSspXXR9gj\n"
			+ "IBBPM5iQn9QwHQYDVR0OBBYEFEjmaPkr0rKV10fYIyAQTzOYkJ/UMAwGA1UdEwQF\n"
			+ "MAMBAf8wGgYJKoZIhvZ9B0EABA0wCxsFVjMuMGMDAgbAMA0GCSqGSIb3DQEBBQUA\n"
			+ "A4GBAFjOKer89961zgK5F7WF0bnj4JXMJTENAKaSbn+2kmOeUJXRmm/kEd5jhW6Y\n"
			+ "7qj/WsjTVbJmcVfewCHrPSqnI0kBBIZCe/zuf6IWUrVnZ9NA2zsmWLIodz2uFHdh\n"
			+ "1voqZiegDfqnc1zqcPGUIWVEX/r87yloqaKHee9570+sB3c4\n" + "-----END CERTIFICATE-----\n";

	private static final String VERISIGN_CLASS_3_EV = "-----BEGIN CERTIFICATE-----\n"
			+ "MIIF5DCCBMygAwIBAgIQW3dZxheE4V7HJ8AylSkoazANBgkqhkiG9w0BAQUFADCB\n"
			+ "yjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL\n"
			+ "ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp\n"
			+ "U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW\n"
			+ "ZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0\n"
			+ "aG9yaXR5IC0gRzUwHhcNMDYxMTA4MDAwMDAwWhcNMTYxMTA3MjM1OTU5WjCBujEL\n"
			+ "MAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZW\n"
			+ "ZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTswOQYDVQQLEzJUZXJtcyBvZiB1c2UgYXQg\n"
			+ "aHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL3JwYSAoYykwNjE0MDIGA1UEAxMrVmVy\n"
			+ "aVNpZ24gQ2xhc3MgMyBFeHRlbmRlZCBWYWxpZGF0aW9uIFNTTCBDQTCCASIwDQYJ\n"
			+ "KoZIhvcNAQEBBQADggEPADCCAQoCggEBAJjboFXrnP0XeeOabhQdsVuYI4cWbod2\n"
			+ "nLU4O7WgerQHYwkZ5iqISKnnnbYwWgiXDOyq5BZpcmIjmvt6VCiYxQwtt9citsj5\n"
			+ "OBfH3doxRpqUFI6e7nigtyLUSVSXTeV0W5K87Gws3+fBthsaVWtmCAN/Ra+aM/EQ\n"
			+ "wGyZSpIkMQht3QI+YXZ4eLbtfjeubPOJ4bfh3BXMt1afgKCxBX9ONxX/ty8ejwY4\n"
			+ "P1C3aSijtWZfNhpSSENmUt+ikk/TGGC+4+peGXEFv54cbGhyJW+ze3PJbb0S/5tB\n"
			+ "Ml706H7FC6NMZNFOvCYIZfsZl1h44TO/7Wg+sSdFb8Di7Jdp91zT91ECAwEAAaOC\n"
			+ "AdIwggHOMB0GA1UdDgQWBBT8ilC6nrklWntVhU+VAGOP6VhrQzASBgNVHRMBAf8E\n"
			+ "CDAGAQH/AgEAMD0GA1UdIAQ2MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIBFhxodHRw\n"
			+ "czovL3d3dy52ZXJpc2lnbi5jb20vY3BzMD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6\n"
			+ "Ly9FVlNlY3VyZS1jcmwudmVyaXNpZ24uY29tL3BjYTMtZzUuY3JsMA4GA1UdDwEB\n"
			+ "/wQEAwIBBjARBglghkgBhvhCAQEEBAMCAQYwbQYIKwYBBQUHAQwEYTBfoV2gWzBZ\n"
			+ "MFcwVRYJaW1hZ2UvZ2lmMCEwHzAHBgUrDgMCGgQUj+XTGoasjY5rw8+AatRIGCx7\n"
			+ "GS4wJRYjaHR0cDovL2xvZ28udmVyaXNpZ24uY29tL3ZzbG9nby5naWYwKQYDVR0R\n"
			+ "BCIwIKQeMBwxGjAYBgNVBAMTEUNsYXNzM0NBMjA0OC0xLTQ3MD0GCCsGAQUFBwEB\n"
			+ "BDEwLzAtBggrBgEFBQcwAYYhaHR0cDovL0VWU2VjdXJlLW9jc3AudmVyaXNpZ24u\n"
			+ "Y29tMB8GA1UdIwQYMBaAFH/TZafC3ey78DAJ80M5+gKvMzEzMA0GCSqGSIb3DQEB\n"
			+ "BQUAA4IBAQCWovp/5j3t1CvOtxU/wHIDX4u6FpAl98KD2Md1NGNoElMMU4l7yVYJ\n"
			+ "p8M2RE4O0GJis4b66KGbNGeNUyIXPv2s7mcuQ+JdfzOE8qJwwG6Cl8A0/SXGI3/t\n"
			+ "5rDFV0OEst4t8dD2SB8UcVeyrDHhlyQjyRNddOVG7wl8nuGZMQoIeRuPcZ8XZsg4\n"
			+ "z+6Ml7YGuXNG5NOUweVgtSV1LdlpMezNlsOjdv3odESsErlNv1HoudRETifLriDR\n"
			+ "fip8tmNHnna6l9AW5wtsbfdDbzMLKTB3+p359U64drPNGLT5IO892+bKrZvQTtKH\n"
			+ "qQ2mRHNQ3XBb7a1+Srwi1agm5MKFIA3Z\n" + "-----END CERTIFICATE-----\n";

	private static final String VERISIGN_CLASS_THREE = "-----BEGIN CERTIFICATE-----\n"
			+ "MIIExjCCBC+gAwIBAgIQNZcxh/OHOgcyfs5YDJt+2jANBgkqhkiG9w0BAQUFADBf\n"
			+ "MQswCQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xNzA1BgNVBAsT\n"
			+ "LkNsYXNzIDMgUHVibGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkw\n"
			+ "HhcNMDYxMTA4MDAwMDAwWhcNMjExMTA3MjM1OTU5WjCByjELMAkGA1UEBhMCVVMx\n"
			+ "FzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVz\n"
			+ "dCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJpU2lnbiwgSW5jLiAtIEZv\n"
			+ "ciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxWZXJpU2lnbiBDbGFzcyAz\n"
			+ "IFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IC0gRzUwggEi\n"
			+ "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvJAgIKXo1nmAMqudLO07cfLw8\n"
			+ "RRy7K+D+KQL5VwijZIUVJ/XxrcgxiV0i6CqqpkKzj/i5Vbext0uz/o9+B1fs70Pb\n"
			+ "ZmIVYc9gDaTY3vjgw2IIPVQT60nKWVSFJuUrjxuf6/WhkcIzSdhDY2pSS9KP6HBR\n"
			+ "TdGJaXvHcPaz3BJ023tdS1bTlr8Vd6Gw9KIl8q8ckmcY5fQGBO+QueQA5N06tRn/\n"
			+ "Arr0PO7gi+s3i+z016zy9vA9r911kTMZHRxAy3QkGSGT2RT+rCpSx4/VBEnkjWNH\n"
			+ "iDxpg8v+R70rfk/Fla4OndTRQ8Bnc+MUCH7lP59zuDMKz10/NIeWiu5T6CUVAgMB\n"
			+ "AAGjggGRMIIBjTAPBgNVHRMBAf8EBTADAQH/MDEGA1UdHwQqMCgwJqAkoCKGIGh0\n"
			+ "dHA6Ly9jcmwudmVyaXNpZ24uY29tL3BjYTMuY3JsMA4GA1UdDwEB/wQEAwIBBjA9\n"
			+ "BgNVHSAENjA0MDIGBFUdIAAwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cudmVy\n"
			+ "aXNpZ24uY29tL2NwczAdBgNVHQ4EFgQUf9Nlp8Ld7LvwMAnzQzn6Aq8zMTMwNAYD\n"
			+ "VR0lBC0wKwYJYIZIAYb4QgQBBgpghkgBhvhFAQgBBggrBgEFBQcDAQYIKwYBBQUH\n"
			+ "AwIwbQYIKwYBBQUHAQwEYTBfoV2gWzBZMFcwVRYJaW1hZ2UvZ2lmMCEwHzAHBgUr\n"
			+ "DgMCGgQUj+XTGoasjY5rw8+AatRIGCx7GS4wJRYjaHR0cDovL2xvZ28udmVyaXNp\n"
			+ "Z24uY29tL3ZzbG9nby5naWYwNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhho\n"
			+ "dHRwOi8vb2NzcC52ZXJpc2lnbi5jb20wDQYJKoZIhvcNAQEFBQADgYEADyWuSO0b\n"
			+ "M4VMDLXC1/5N1oMoTEFlYAALd0hxgv5/21oOIMzS6ke8ZEJhRDR0MIGBJopK90Rd\n"
			+ "fjSAqLiD4gnXbSPdie0oCL1jWhFXCMSe2uJoKK/dUDzsgiHYAMJVRFBwQa2DF3m6\n"
			+ "CPMr3u00HUSe0gST9MsFFy0JLS1j7/YmC3s=\n" + "-----END CERTIFICATE-----\n";

	private static final String VERISIGN_ROOT = "-----BEGIN CERTIFICATE-----\n"
			+ "MIICPDCCAaUCEHC65B0Q2Sk0tjjKewPMur8wDQYJKoZIhvcNAQECBQAwXzELMAkG\n"
			+ "A1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMTcwNQYDVQQLEy5DbGFz\n"
			+ "cyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTk2\n"
			+ "MDEyOTAwMDAwMFoXDTI4MDgwMTIzNTk1OVowXzELMAkGA1UEBhMCVVMxFzAVBgNV\n"
			+ "BAoTDlZlcmlTaWduLCBJbmMuMTcwNQYDVQQLEy5DbGFzcyAzIFB1YmxpYyBQcmlt\n"
			+ "YXJ5IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIGfMA0GCSqGSIb3DQEBAQUAA4GN\n"
			+ "ADCBiQKBgQDJXFme8huKARS0EN8EQNvjV69qRUCPhAwL0TPZ2RHP7gJYHyX3KqhE\n"
			+ "BarsAx94f56TuZoAqiN91qyFomNFx3InzPRMxnVx0jnvT0Lwdd8KkMaOIG+YD/is\n"
			+ "I19wKTakyYbnsZogy1Olhec9vn2a/iRFM9x2Fe0PonFkTGUugWhFpwIDAQABMA0G\n"
			+ "CSqGSIb3DQEBAgUAA4GBALtMEivPLCYATxQT3ab7/AoRhIzzKBxnki98tsX63/Do\n"
			+ "lbwdj2wsqFHMc9ikwFPwTtYmwHYBV4GSXiHx0bH/59AhWM1pF+NEHJwZRDmJXNyc\n"
			+ "AA9WjQKZ7aKQRUzkuxCkPfAyAw7xzvjoyVGM5mKf5p/AfbdynMk2OmufTqj/ZA1k\n" + "-----END CERTIFICATE-----\n";

	public X509Certificate[] getAcceptedIssuers() {
		return null;
	}

	private byte[] hexStringToByteArray(String s) {
		final int len = s.length();
		final byte[] data = new byte[len / 2];

		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}

		return data;
	}

	public void clearCache() {
		cache.clear();
	}
}
