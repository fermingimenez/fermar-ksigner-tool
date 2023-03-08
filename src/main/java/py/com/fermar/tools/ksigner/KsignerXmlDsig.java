package py.com.fermar.tools.ksigner;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.opensaml.core.config.InitializationException;
import org.opensaml.security.x509.X509Credential;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class KsignerXmlDsig {

	public static Document signXmlDocument(Document inXml, String certPath, String keyPath, DigestChoice signDigest)
			throws SigningException {
	
		try {
			InitializationSupport.initialize();
		} catch (InitializationException e) {
			throw new SigningException("Error al inicializar el firmador.", e);
		}

		final String[] args = { "--sign", "--inFile", "fakeIn.xml", "--outFile", "fakeOut.xml", "--certificate",
				certPath, "--key", keyPath, "--digest", signDigest.getOtherName(), "--whitelistDigest",
				signDigest.getOtherName() };

		final X509Credential credential;
		try {
			credential = CredentialHelper.getFileBasedCredentials(keyPath, null, certPath);
		} catch (KeyException | CertificateException e) {
			throw new SigningException("Error al procesar las credenciales. Verificar el Key y/o el Certificado.", e);
		}

		final CommandLineArguments cli = new CommandLineArguments();
		cli.parseCommandLineArguments(args);
		XMLSecTool.initLogging(cli);

		try {
			// Se firma el documento
			XMLSecTool.sign(cli, credential, inXml);

			// Se verifica la firma con fines de consistencia
			XMLSecTool.verifySignature(cli, credential, inXml);

			return inXml;

		} catch (RuntimeException e) {
			throw new SigningException("Excepción durante la firma del documento.", e);
		}

	}
	
	public static Document signXmlDocument(Document inXml, String certPath, KeyStore keystore, 
										   String keyAlias, String keyPassword, DigestChoice signDigest) throws SigningException {
	
		try {
			InitializationSupport.initialize();
		} catch (InitializationException e) {
			throw new SigningException("Error al inicializar el firmador.", e);
		}

		final String[] args = { "--sign", "--inFile", "fakeIn.xml", "--outFile", "fakeOut.xml", "--certificate",
				certPath, "--key", "fakeKeyPath.xml", "--digest", signDigest.getOtherName(), "--whitelistDigest",
				signDigest.getOtherName(), "--signaturePosition", "LAST", "--referenceIdAttributeName", "DE"};

		final X509Credential credential;
		try {
			credential = CredentialHelper.getCredentialFromKeystore(keystore, keyAlias, keyPassword);
		} catch (GeneralSecurityException e) {
			throw new SigningException("Error al procesar las credenciales. Verificar el Key y/o el Certificado.", e);
		}

		final CommandLineArguments cli = new CommandLineArguments();
		cli.parseCommandLineArguments(args);
		XMLSecTool.initLogging(cli);

		try {
			// Se firma el documento
			XMLSecTool.sign(cli, credential, inXml);

			// Se verifica la firma con fines de consistencia
			XMLSecTool.verifySignature(cli, credential, inXml);

			return inXml;

		} catch (RuntimeException e) {
			throw new SigningException("Excepción durante la firma del documento.", e);
		}

	}

	public static void signXmlFile(String inPath, String outPath, String certPath, String keyPath,
			DigestChoice signDigest) throws SigningException {

		try {
			InitializationSupport.initialize();
		} catch (InitializationException e) {
			throw new SigningException("Error al inicializar el firmador.", e);
		}

		final String[] args = { "--sign", "--inFile", inPath, "--outFile", outPath, "--certificate", certPath, "--key",
				keyPath, "--digest", signDigest.getOtherName(), "--whitelistDigest",
				signDigest.getOtherName()};
		

		final X509Credential credential;
		try {
			credential = CredentialHelper.getFileBasedCredentials(keyPath, null, certPath);
		} catch (KeyException | CertificateException e) {
			throw new SigningException("Error al procesar las credenciales. Verificar el Key y/o el Certificado.", e);
		}

		final CommandLineArguments cli = new CommandLineArguments();
		cli.parseCommandLineArguments(args);
		XMLSecTool.initLogging(cli);

		final Document inXml;
		try {
			inXml = readXMLDocument(inPath);
		} catch (DocumentReadException e) {
			throw new SigningException("No se puede firmar el documento XML.", e);
		}

		try {
			// Se firma el documento
			XMLSecTool.sign(cli, credential, inXml);
			// Se verifica la firma con fines de consistencia
			XMLSecTool.verifySignature(cli, credential, inXml);

			XMLSecTool.writeDocument(cli, inXml);

		} catch (RuntimeException e) {
			throw new SigningException("Excepción durante la firma del documento.", e);
		}

	}

	public static Document readXMLDocument(String inPath) throws DocumentReadException {
		try (InputStream input = new FileInputStream(inPath)) {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			DocumentBuilder builder = dbf.newDocumentBuilder();
			return builder.parse(input);
		} catch (ParserConfigurationException | IOException | SAXException e) {
			throw new DocumentReadException("No se pudo leer el archivo XML", e);
		}

	}
	
	public static void verifySignature(String inPath) throws SignVerificationException {
		Document inXml;
		try {
			inXml = readXMLDocument(inPath);
		} catch (DocumentReadException e) {
			throw new SignVerificationException("Excepción durante la lectura del documento.", e);
		}
		
		validateSignature(inXml);
	}
	
	public static void verifySignature(String inPath, String certPath) throws SignVerificationException {
		
		final String[] args = {
				"--verifySignature", 
				"--inFile", "fakeIn.xml",
				"--certificate", certPath};
		
		try {
			InitializationSupport.initialize();
		} catch (InitializationException e) {
			throw new SignVerificationException(String.format("Error al inicializar el firmador. %s", e.getMessage()));
		}
		
		final CommandLineArguments cli = new CommandLineArguments();
		cli.parseCommandLineArguments(args);
		
		Document inXml;
		try {
			inXml = readXMLDocument(inPath);
		} catch (DocumentReadException e) {
			throw new SignVerificationException(String.format("Excepción durante la lectura del documento.", e.getMessage()));
		}
		
		try {
			final X509Credential cred = XMLSecTool.getCredential(cli);
			XMLSecTool.verifySignature(cli, cred, inXml);

		} catch (RuntimeException e) {
			throw new SignVerificationException(String.format("Excepción durante verificación de la firma del documento. %s", e.getMessage()));
		}
	}

	@SuppressWarnings("rawtypes")
	public static void validateSignature(Document signedXml) throws SignVerificationException {

		// Find Signature element
		NodeList nl = signedXml.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
		if (nl.getLength() == 0) {
			throw new SignVerificationException("No se encuentra el elemento Signarure.");
		}

		// Create a DOM XMLSignatureFactory that will be used to unmarshal the
		// document containing the XMLSignature
		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

		// Create a DOMValidateContext and specify a KeyValue KeySelector
		// and document context
		DOMValidateContext valContext = new DOMValidateContext(new X509KeySelector(), nl.item(0));

		try {
			// unmarshal the XMLSignature
			XMLSignature signature = fac.unmarshalXMLSignature(valContext);

			// Validate the XMLSignature (generated above)
			boolean coreValidity = signature.validate(valContext);
			
			// Check core validation status.
			if (!coreValidity) {
			    System.err.println("Signature failed core validation");
			    boolean sv = signature.getSignatureValue().validate(valContext);
			    System.out.println(String.format("signature validation status: %b", sv));
			    if (!sv) {
			        // Check the validation status of each Reference.
			        Iterator i = signature.getSignedInfo().getReferences().iterator();
			        for (int j=0; i.hasNext(); j++) {
			            boolean refValid = ((Reference) i.next()).validate(valContext);
			            System.out.println(String.format("ref[%d] validity status: %b", j, refValid));
			        }
			    }    
			    throw new InvalidSignatureException("Signature failed core validation");
			    
			}
		} catch (Exception e) {
			throw new SignVerificationException(e.getMessage());
		}
	}


	private static class X509KeySelector extends KeySelector {
	    @SuppressWarnings("rawtypes")
		public KeySelectorResult select(KeyInfo keyInfo,
	                                    KeySelector.Purpose purpose,
	                                    AlgorithmMethod method,
	                                    XMLCryptoContext context)
	        throws KeySelectorException {
	        Iterator ki = keyInfo.getContent().iterator();
	        while (ki.hasNext()) {
	            XMLStructure info = (XMLStructure) ki.next();
	            if (!(info instanceof X509Data))
	                continue;
	            X509Data x509Data = (X509Data) info;
	            Iterator xi = x509Data.getContent().iterator();
	            while (xi.hasNext()) {
	                Object o = xi.next();
	                if (!(o instanceof X509Certificate))
	                    continue;
	                final PublicKey key = ((X509Certificate)o).getPublicKey();
	                
	                // Make sure the algorithm is compatible
	                // with the method.
	                if (algEquals(method.getAlgorithm(), key.getAlgorithm())) {
	                    return new KeySelectorResult() {
	                        public Key getKey() { return key; }
	                    };
	                }
	            }
	        }
	        throw new KeySelectorException("No key found!");
	    }

		// this should also work for key types other than DSA/RSA
		static boolean algEquals(String algURI, String algName) {
			if (algName.equalsIgnoreCase("DSA") && (algURI.equalsIgnoreCase(W3CSignatureMethods.DSA_SHA1)
					|| algURI.equalsIgnoreCase(W3CSignatureMethods.DSA_SHA256))) {
				return true;
			} else if (algName.equalsIgnoreCase("RSA") && (algURI.equalsIgnoreCase(W3CSignatureMethods.RSA_MD5)
					|| algURI.equalsIgnoreCase(W3CSignatureMethods.RSA_RIPEMD160)
					|| algURI.equalsIgnoreCase(W3CSignatureMethods.RSA_SHA224)
					|| algURI.equalsIgnoreCase(W3CSignatureMethods.RSA_SHA256)
					|| algURI.equalsIgnoreCase(W3CSignatureMethods.RSA_SHA384)
					|| algURI.equalsIgnoreCase(W3CSignatureMethods.RSA_SHA512)
					|| algURI.equalsIgnoreCase(W3CSignatureMethods.RSA_SHA1))) {

				return true;

			} else if (algName.equalsIgnoreCase("ECDSA") && (algURI.equalsIgnoreCase(W3CSignatureMethods.ECDSA_SHA1)
					|| algURI.equalsIgnoreCase(W3CSignatureMethods.ECDSA_SHA224)
					|| algURI.equalsIgnoreCase(W3CSignatureMethods.ECDSA_SHA256)
					|| algURI.equalsIgnoreCase(W3CSignatureMethods.ECDSA_SHA384)
					|| algURI.equalsIgnoreCase(W3CSignatureMethods.ECDSA_SHA512))) {

				return true;

			} else if (algName.equalsIgnoreCase("HMAC") && (algURI.equalsIgnoreCase(W3CSignatureMethods.HMAC_RIPEMD160)
					|| algURI.equalsIgnoreCase(W3CSignatureMethods.HMAC_SHA1)
					|| algURI.equalsIgnoreCase(W3CSignatureMethods.HMAC_SHA224)
					|| algURI.equalsIgnoreCase(W3CSignatureMethods.HMAC_SHA256)
					|| algURI.equalsIgnoreCase(W3CSignatureMethods.HMAC_SHA384)
					|| algURI.equalsIgnoreCase(W3CSignatureMethods.HMAC_SHA512))) {

				return true;

			} else {
				return false;
			}
		}
	}

}
