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
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.w3c.dom.Document;

public class XmlSifenTest {
	
	private static KeyStore ks;
	private static KeyStore ksSet;
	private String fileOut;

	/**
	 * Carga el Keystore a ser utilizado por los métodos de test.
	 * 
	 * @throws KeyStoreException
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 */
	@BeforeClass
	public static void initKeystoreTest() throws KeyStoreException, FileNotFoundException, IOException, 
		NoSuchAlgorithmException, CertificateException {
		ks = KeyStore.getInstance("JKS");
		URL keystoreURL = 
				KsignerXmlDsigTest.class
						.getResource("/py/com/konecta/tools/ksigner/sifen/keystoreKonecta.jks");
		String storename = keystoreURL.getPath();
		char[] storepass = "4jd3GAd35U3skXJ8".toCharArray();
		try (FileInputStream fin = new FileInputStream(storename)) {
			ks.load(fin, storepass);
		}
	}
	
	/**
	 * Inicializa el keystore utilizado por documentos de la set
	 * @throws KeyStoreException
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 */
	@BeforeClass
	public static void initKeystoreLucho() throws KeyStoreException, FileNotFoundException, IOException, 
		NoSuchAlgorithmException, CertificateException {
		ksSet = KeyStore.getInstance("JKS");
		URL keystoreURL = 
				KsignerXmlDsigTest.class
						.getResource("/py/com/konecta/tools/ksigner/sifen/pruebaLucho.jks");
		String storename = keystoreURL.getPath();
		char[] storepass = "qwerty".toCharArray();
		try (FileInputStream fin = new FileInputStream(storename)) {
			ksSet.load(fin, storepass);
		}
	}
	
	/**
	 * Genera un xml firmado(con signature fuera del tag firmado,
	 * y con reference URI seteado en el signature)
	 * @throws Exception
	 */
	//@Test	
	public void testSignXmlSifenWithCryptoDsig() throws Exception {
		URL fUrl = getClass().getResource("/py/com/konecta/tools/ksigner/sifen/rDEV141-vero.xml");
		Document signedXmlDocument = SignXmlSifenWithCryptoDsig.signDocument(fUrl.getPath(), ks, "4jd3GAd35U3skXJ8", "cambiar");
		
		// Escribimos el contenido en un archivo .xml
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		Transformer transformer = transformerFactory.newTransformer();
		DOMSource source = new DOMSource(signedXmlDocument);
		StreamResult result = new StreamResult(new File("C:\\Proyectos\\SIFEN\\certificados-keystore\\rDEV141-vero.xml"));
		transformer.transform(source, result);
		System.out.println("File saved!");	
	}
	
	/**
	 * Genera un xml firmado(con signature fuera del tag firmado,
	 * y con reference URI seteado en el signature)
	 * @throws Exception
	 */
	//@Test	
	public void testSignXmlSifenWithCryptoDsigEvento() throws Exception {
		URL fUrl = getClass().getResource("/py/com/konecta/tools/ksigner/sifen/cancelacion01.xml");
		Document signedXmlDocument = SignXmlSifenWithCryptoDsig.signDocument(fUrl.getPath(), ks, "4jd3GAd35U3skXJ8","cambiar");
		
		// Escribimos el contenido en un archivo .xml
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		Transformer transformer = transformerFactory.newTransformer();
		DOMSource source = new DOMSource(signedXmlDocument);
		StreamResult result = new StreamResult(new File("C:\\Proyectos\\SIFEN\\certificados-keystore\\cancelacion01.xml"));
		transformer.transform(source, result);
		System.out.println("File saved!");
	}
	
	/**
	 * Genera xml firmado con certificado de una CA autorizada 
	 * @throws Exception
	 */
	//@Test	
	public void testSignXmlSifenWithCryptoDsigSetEventos() throws Exception {
		URL fUrl = getClass().getResource("/py/com/konecta/tools/ksigner/sifen/EveCancEnvSet.xml");
		
		Document signedXmlDocument = SignXmlSifenWithCryptoDsig.signDocument(fUrl.getPath(), ksSet, "qwerty", "cambiar");
		
		// Escribimos el contenido en un archivo .xml
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		Transformer transformer = transformerFactory.newTransformer();
		DOMSource source = new DOMSource(signedXmlDocument);
		StreamResult result = new StreamResult(new File("C:\\Proyectos\\SIFEN\\certificados-keystore\\EveCancEnvSet.xml"));
		transformer.transform(source, result);
		System.out.println("File saved!");	
	}
	
	/**
	 * Genera un xml firmado(con signature dentro del tag firmado)
	 * @throws Exception
	 */
	//@Test	
	public void testSignXmlDocumentWithKeystoreSifen() throws Exception {
		URL fUrl = getClass().getResource("/py/com/konecta/tools/ksigner/sifen/DEV141-CAMBIOS.xml");
		URL certUrl = getClass().getResource("/py/com/konecta/tools/ksigner/sifen/keystoreKonecta.cer");
		fileOut= fUrl.toURI().getPath().replace(".xml", "") + "-signed.xml";

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
												   "sifen", "4jd3GAd35U3skXJ8", DigestChoice.SHA256);
			
			KsignerXmlDsig.validateSignature(signedXmlDocument);
			//copiar en el archivo
			try {
				// escribimos el contenido en un archivo .xml
				TransformerFactory transformerFactory = TransformerFactory.newInstance();
				Transformer transformer = transformerFactory.newTransformer();
				DOMSource source = new DOMSource(signedXmlDocument);
				StreamResult result = new StreamResult(new File(fileOut));
				transformer.transform(source, result);
				
				System.out.println("File saved!");
			} catch (TransformerException tfe) {
				tfe.printStackTrace();
			}
		}
	}
	
	/**
	 * validamos la firma dentro del xml 
	 * Se puede agregar boolean de retorno
	 * @throws Exception
	 */
	//@Test
	public void testverifySignature() throws Exception {
		URL fUrl = getClass().getResource("/py/com/konecta/tools/ksigner/sifen/FEV141-FINAL-CanoIncl.xml");
		KsignerXmlDsig.verifySignature(fUrl.getPath());
	}

}
