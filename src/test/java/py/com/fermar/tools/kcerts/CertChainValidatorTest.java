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

public class CertChainValidatorTest {

	private static KeyStore ks;

	/**
	 * Carga el Keystore a ser utilizado por los métodos de test.
	 * 
	 * @throws KeyStoreException
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 */
	@BeforeClass(enabled = false)
	public static void initKeystore() throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException {
		ks = KeyStore.getInstance("JKS");
		URL keystoreURL = 
				CertChainValidatorTest.class
						.getResource("/py/com/konecta/tools/kcerts/KCertsKeystore.jks");
		String storename = keystoreURL.getPath();
		char[] storepass = "secretsecret".toCharArray();
		try (FileInputStream fin = new FileInputStream(storename)) {
			ks.load(fin, storepass);
		}
	}

	/**
	 * Valida un certificado válido. Se espera que la validación retorn
	 * {@code true} .
	 * 
	 * @throws KeyStoreException
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws NoSuchProviderException
	 */
	//@Test(enabled = false)
	public void testValidateKeyChainWithValidCertChain()
			throws KeyStoreException, FileNotFoundException, IOException, CertificateException,
			NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
		X509Certificate certificate = loadCertFromResourcePath("/py/com/konecta/tools/kcerts/konectacompy.cer");
		boolean result = CertChainValidator.validateKeyChain(certificate, ks);
		Assert.assertTrue(result);
	}

	/**
	 * Valida un certificado inválido. Se espera que la validación retorne
	 * {@code false}.
	 * 
	 * @throws KeyStoreException
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws NoSuchProviderException
	 */
	//@Test(enabled = false)
	public void testValidateKeyChainWithInvalidCertChain()
			throws KeyStoreException, FileNotFoundException, IOException, CertificateException,
			NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
		X509Certificate certificate = loadCertFromResourcePath("/py/com/konecta/tools/ksigner/XSTJ59-dsa1024.crt");
		boolean result = CertChainValidator.validateKeyChain(certificate, ks);
		Assert.assertFalse(result);
	}

	/**
	 * Instancia un X509Certificate a partir de un archivo .cert
	 * 
	 * @param path
	 * @return
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws CertificateException
	 */
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
