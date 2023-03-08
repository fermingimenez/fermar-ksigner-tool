package py.com.fermar.tools.ksigner;

import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import net.shibboleth.utilities.java.support.primitive.StringSupport;

public class SignXmlSifenWithCryptoDsig {
	
	/**
	 * Método utilizado para firmar documentos de sifen con canonización 
	 * exclusiva 
	 * Signature fuera del tag firmado y referencia asignada al signature
	 * @param pathXMLDocument
	 * @param keystore
	 * @throws SigningException 
	 */
	public static Document signDocument(String pathXMLDocument, KeyStore keystore, String password, String alias) throws SigningException {    
		String ref = "";
		Document inXml = null;
        try {
    		inXml = KsignerXmlDsig.readXMLDocument(pathXMLDocument);
  
    		// Marque el atributo de referencia como un atributo de ID válido
    		Element id = (Element) inXml.getChildNodes().item(0).getChildNodes().item(1);
			if(id.getAttributes().getNamedItem("Id")!= null) { 
				id.setIdAttributeNS(null, "Id", true);
				ref = StringSupport.trim(id.getAttributes().getNamedItem("Id").getNodeValue());
				if (ref.length() > 0) {
					ref = "#" + ref;
				}
			}
			
			 /* Primero, crea un DOM XMLSignatureFactory que se usará para
			   generar XMLSignature y dirígelo a DOM.*/
            XMLSignatureFactory factory = 
                    XMLSignatureFactory.getInstance("DOM");
 
            // Usamos el SHA256 digest algorithm
            DigestMethod digestMethod = factory.newDigestMethod(DigestMethod.SHA256, null);
            //"http://www.w3.org/2000/09/xmldsig#enveloped-signature"
            Transform envTransform = factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);
            // Canonización exclusiva "http://www.w3.org/2001/10/xml-exc-c14n#"
            Transform exc14nTransform = factory.newTransform(SignatureConstants.
            		TRANSFORM_C14N_EXCL_OMIT_COMMENTS, (TransformParameterSpec) null);
            
            @SuppressWarnings("rawtypes")
            ArrayList transformList = new ArrayList();
            transformList.add(envTransform);
            transformList.add(exc14nTransform);            
            
            //Creamos una referencia a un URI externo que será digested
            Reference reference = factory.newReference(ref, digestMethod, transformList, null, null);
            //Algoritmo inclusivo "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
            CanonicalizationMethod canonicalizationMethod = 
                    factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null);
            SignatureMethod signatureMethod = factory.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null);
            // Creamos el SignedInfo
            SignedInfo signedInfo = factory.newSignedInfo(canonicalizationMethod, signatureMethod, 
            		Collections.singletonList(reference));
 
            PrivateKeyEntry keyEntry = null;
            PublicKey publicKey = null;
            PrivateKey privateKey = null;
            X509Certificate cert = null;
           
            KeyInfoFactory keyInfoFactory = factory.getKeyInfoFactory();
            keyEntry = (PrivateKeyEntry) keystore.getEntry(alias,
                    new KeyStore.PasswordProtection(password.toCharArray()));
            cert = (X509Certificate) keyEntry.getCertificate();
            publicKey = cert.getPublicKey();
            privateKey = keyEntry.getPrivateKey();               
 
            @SuppressWarnings("rawtypes")
            List x509 = new ArrayList();
            X509IssuerSerial issuer = keyInfoFactory.newX509IssuerSerial
                    (cert.getIssuerX500Principal().getName(), cert.getSerialNumber());
            x509.add(cert);
            x509.add(issuer);
            // Creamos un KeyValue que contenga RSA PublicKey
            KeyValue keyValue = keyInfoFactory.newKeyValue(publicKey);
            X509Data x509Data = keyInfoFactory.newX509Data(x509);
            KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(x509Data));            
            // Creamos un DOMSignContext y especificamos el RSA PrivateKey y
            // localización del XMLSignature's parent element
            DOMSignContext dsc = new DOMSignContext(privateKey, inXml.getDocumentElement());
            // Create the XMLSignature (but don't sign it yet)
            XMLSignature signature = factory.newXMLSignature(signedInfo, keyInfo);
            // Marshal, generate (and sign) the enveloped signature
            signature.sign(dsc);
			
        } catch (Exception e) {
        	throw new SigningException("Excepción durante la firma del documento.", e);
        }
		return inXml; 
 
    }
	
	public static Document signEvent(String pathXMLDocument, KeyStore keystore, String password, String alias) throws SigningException {    
		String ref = "";
		Document inXml = null;
        try {
    		inXml = KsignerXmlDsig.readXMLDocument(pathXMLDocument);
  
    		// Marque el atributo de referencia como un atributo de ID válido
    		Element id = (Element) inXml.getChildNodes().item(0).getChildNodes().item(0);
			if(id.getAttributes().getNamedItem("Id")!= null) { 
				id.setIdAttributeNS(null, "Id", true);
				ref = StringSupport.trim(id.getAttributes().getNamedItem("Id").getNodeValue());
				if (ref.length() > 0) {
					ref = "#" + ref;
				}
			}
			
			 /* Primero, crea un DOM XMLSignatureFactory que se usará para
			   generar XMLSignature y dirígelo a DOM.*/
            XMLSignatureFactory factory = 
                    XMLSignatureFactory.getInstance("DOM");
 
            // Usamos el SHA256 digest algorithm
            DigestMethod digestMethod = factory.newDigestMethod(DigestMethod.SHA256, null);
            //"http://www.w3.org/2000/09/xmldsig#enveloped-signature"
            Transform envTransform = factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);
            // Canonización exclusiva "http://www.w3.org/2001/10/xml-exc-c14n#"
            Transform exc14nTransform = factory.newTransform(SignatureConstants.
            		TRANSFORM_C14N_EXCL_OMIT_COMMENTS, (TransformParameterSpec) null);
            
            @SuppressWarnings("rawtypes")
            ArrayList transformList = new ArrayList();
            transformList.add(envTransform);
            transformList.add(exc14nTransform);            
            
            //Creamos una referencia a un URI externo que será digested
            Reference reference = factory.newReference(ref, digestMethod, transformList, null, null);
            //Algoritmo inclusivo "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
            CanonicalizationMethod canonicalizationMethod = 
                    factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null);
            SignatureMethod signatureMethod = factory.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null);
            // Creamos el SignedInfo
            SignedInfo signedInfo = factory.newSignedInfo(canonicalizationMethod, signatureMethod, 
            		Collections.singletonList(reference));
 
            PrivateKeyEntry keyEntry = null;
            PublicKey publicKey = null;
            PrivateKey privateKey = null;
            X509Certificate cert = null;
           
            KeyInfoFactory keyInfoFactory = factory.getKeyInfoFactory();
            keyEntry = (PrivateKeyEntry) keystore.getEntry(alias,
                    new KeyStore.PasswordProtection(password.toCharArray()));
            cert = (X509Certificate) keyEntry.getCertificate();
            publicKey = cert.getPublicKey();
            privateKey = keyEntry.getPrivateKey();               
 
            @SuppressWarnings("rawtypes")
            List x509 = new ArrayList();
            X509IssuerSerial issuer = keyInfoFactory.newX509IssuerSerial
                    (cert.getIssuerX500Principal().getName(), cert.getSerialNumber());
            x509.add(cert);
            x509.add(issuer);
            // Creamos un KeyValue que contenga RSA PublicKey
            KeyValue keyValue = keyInfoFactory.newKeyValue(publicKey);
            X509Data x509Data = keyInfoFactory.newX509Data(x509);
            KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(x509Data));            
            // Creamos un DOMSignContext y especificamos el RSA PrivateKey y
            // localización del XMLSignature's parent element
            DOMSignContext dsc = new DOMSignContext(privateKey, inXml.getDocumentElement());
            // Create the XMLSignature (but don't sign it yet)
            XMLSignature signature = factory.newXMLSignature(signedInfo, keyInfo);
            // Marshal, generate (and sign) the enveloped signature
            signature.sign(dsc);
			
        } catch (Exception e) {
        	throw new SigningException("Excepción durante la firma del documento.", e);
        }
		return inXml; 
 
    }
}
