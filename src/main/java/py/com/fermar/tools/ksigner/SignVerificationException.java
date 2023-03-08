package py.com.fermar.tools.ksigner;

public class SignVerificationException extends Exception {
	public SignVerificationException(String message) {
		super(message);
	}
	
	public SignVerificationException(String message, Throwable cause) {
		super(message, cause);
	}
}
