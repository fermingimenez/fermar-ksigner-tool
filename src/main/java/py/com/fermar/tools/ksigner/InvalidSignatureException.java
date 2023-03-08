package py.com.fermar.tools.ksigner;

public class InvalidSignatureException extends Exception {

	public InvalidSignatureException(String message) {
		super(message);
	}
	
	public InvalidSignatureException(String message, Throwable cause) {
		super(message, cause);
	}

}
