package py.com.fermar.tools.ksigner;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.w3c.dom.Document;

public class KsignerXmlDsigTest {
	
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
				KsignerXmlDsigTest.class
						.getResource("/py/com/konecta/tools/ksigner/keystore.jks");
		String storename = keystoreURL.getPath();
		char[] storepass = "foobanksecret".toCharArray();
		try (FileInputStream fin = new FileInputStream(storename)) {
			ks.load(fin, storepass);
		}
	}

	@Test(enabled = false)
	public void testverifySignature() throws Exception {
		URL fUrl = getClass().getResource("/py/com/konecta/tools/ksigner/XSTJ59-out1024.xml");
		KsignerXmlDsig.verifySignature(fUrl.getPath());
	}
	
	@Test(expectedExceptionsMessageRegExp=".*Digest algorithm .* is blacklisted.*", expectedExceptions={SignVerificationException.class}
	,enabled = false)
	public void testverifySignatureWithCertPathBlackListedAlgFailure() throws Exception {
		URL fUrl = getClass().getResource("/py/com/konecta/tools/ksigner/XSTJ59-out1024.xml");
		URL cUrl = getClass().getResource("/py/com/konecta/tools/ksigner/XSTJ59-dsa1024.crt");
		KsignerXmlDsig.verifySignature(fUrl.getPath(), cUrl.getPath());
	}

	@Test(expectedExceptions={SignVerificationException.class},enabled = false)
	public void testValidateSignatureFailed() throws Exception {
		URL fUrl = getClass().getResource("/py/com/konecta/tools/ksigner/notes-signed-tampered.xml");
		KsignerXmlDsig.verifySignature(fUrl.getPath());
	}

	@Test(enabled = false)
	public void testSignXmlFile() throws Exception {
		URL fUrl = getClass().getResource("/py/com/konecta/tools/ksigner/test-unsigned-file.xml");
		URL certUrl = getClass().getResource("/py/com/konecta/tools/ksigner/testRSA_SHA256.cert");
		URL keyUrl = getClass().getResource("/py/com/konecta/tools/ksigner/testRSA1024.key");

		File signedXml = new File(fUrl.toURI().getPath() + "-signed.xml");
		if (signedXml.exists()) {
			signedXml.delete();
		}
		
		try (FileInputStream unsigned = new FileInputStream(new File(fUrl.toURI()));
				FileOutputStream signedOs = new FileOutputStream(signedXml);
				FileInputStream signed = new FileInputStream(new File(fUrl.toURI()))) {

			KsignerXmlDsig.signXmlFile(fUrl.getPath(), signedXml.getAbsolutePath(), certUrl.getPath(), keyUrl.getPath(), DigestChoice.SHA256);
			KsignerXmlDsig.verifySignature(signedXml.getAbsolutePath());
		}
	}
	
	@Test(enabled = false)	
	public void testSignXmlDocumentWithKestore() throws Exception {
		URL fUrl = getClass().getResource("/py/com/konecta/tools/ksigner/gote-unsigned.xml");
		URL certUrl = getClass().getResource("/py/com/konecta/tools/ksigner/foobank.com.py.cer");

		File signedXml = new File(fUrl.toURI().getPath() + "-signed.xml");
		if (signedXml.exists()) {
			signedXml.delete();
		}
		
		try (FileInputStream unsigned = new FileInputStream(new File(fUrl.toURI()));
				FileOutputStream signedOs = new FileOutputStream(signedXml);
				FileInputStream signed = new FileInputStream(new File(fUrl.toURI()))) {
			
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			DocumentBuilder builder = dbf.newDocumentBuilder();
			Document xmlUsignedDocument = builder.parse(unsigned);
			
			Document signedXmlDocument = 
					KsignerXmlDsig.signXmlDocument(xmlUsignedDocument, certUrl.getPath(), ks, 
												   "foobank.com.py", "foobanksecret", DigestChoice.SHA256);
			
			KsignerXmlDsig.validateSignature(signedXmlDocument);
		}
	}
}
