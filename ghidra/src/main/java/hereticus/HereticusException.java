package hereticus;

/** The hereticus tool could not run, or wrote something this extension cannot read. */
public final class HereticusException extends Exception {

	private static final long serialVersionUID = 1L;

	public HereticusException(String message) {
		super(message);
	}

	public HereticusException(String message, Throwable cause) {
		super(message, cause);
	}
}
