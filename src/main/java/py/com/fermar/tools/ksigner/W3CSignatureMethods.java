package py.com.fermar.tools.ksigner;

import javax.xml.crypto.dsig.SignatureMethod;

public interface W3CSignatureMethods extends SignatureMethod {
	
	public static final String DSA_SHA256 = "http://www.w3.org/2009/xmldsig11#dsa-sha256";
	
	public static final String RSA_MD5 = "http://www.w3.org/2001/04/xmldsig-more#rsa-md5";
	
	public static final String RSA_SHA224 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224";
	
	public static final String RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

	public static final String RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";

	public static final String RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
	
	public static final String RSA_RIPEMD160 = "http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160";
	
	public static final String ECDSA_SHA1 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";

	public static final String ECDSA_SHA224 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224";

	public static final String ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";

	public static final String ECDSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";

	public static final String ECDSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
	
	public static final String HMAC_SHA1 = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";

	public static final String HMAC_SHA224 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha224";

	public static final String HMAC_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";
	
	public static final String HMAC_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384";

	public static final String HMAC_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512";
	
	public static final String HMAC_RIPEMD160 = "http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160";
}
