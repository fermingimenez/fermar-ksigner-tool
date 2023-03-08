package py.com.fermar.tools.ksigner;

public class SigningException extends Exception {
	public SigningException(String message) {
		super(message);
	}
	
	public SigningException(String message, Throwable cause) {
		super(message, cause);
	}
}
