package py.com.fermar.tools.kcerts;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class CertChainValidatorSifenTest {
	private static KeyStore ks;
	
	@BeforeClass(enabled = true)
	public static void initKeystore() throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException {
		ks = KeyStore.getInstance("JKS");
		URL keystoreURL = 
				CertChainValidatorTest.class
						.getResource("/py/com/konecta/tools/kcerts/sifen/KCertsKeystoreSifen.jks");
		String storename = keystoreURL.getPath();
		char[] storepass = "4jd3GAd35U3skXJ8".toCharArray();
		try (FileInputStream fin = new FileInputStream(storename)) {
			ks.load(fin, storepass);
		}
	}
	
	//@Test(enabled = true)
	public void testValidateKeyChainWithValidCertChain()
			throws KeyStoreException, FileNotFoundException, IOException, CertificateException,
			NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
		X509Certificate certificate = loadCertFromResourcePath("/py/com/konecta/tools/kcerts"
				+ "/sifen/keystoreKonecta.cer");
		boolean result = CertChainValidator.validateKeyChain(certificate, ks);
		Assert.assertTrue(result);
	}
	
	@SuppressWarnings("rawtypes")
	public X509Certificate loadCertFromResourcePath(String path)
			throws FileNotFoundException, IOException, CertificateException {
		URL certificateUrl = getClass().getResource(path);
		X509Certificate certificate = null;
		try (FileInputStream certFis = new FileInputStream(certificateUrl.getPath())) {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			Collection c = cf.generateCertificates(certFis);
			Iterator i = c.iterator();
			while (i.hasNext()) {
				certificate = (X509Certificate) i.next();
			}
		}
		return certificate;
	}
}
