package hereticus;

import com.google.gson.Gson;
import com.google.gson.JsonParseException;

/** Reads the JSON hereticus prints. */
final class Json {

	private static final Gson GSON = new Gson();

	private Json() {
	}

	/**
	 * Reads `json` as a `type`.
	 *
	 * @throws HereticusException if the text is not JSON of that shape
	 */
	static <T> T parse(String json, Class<T> type) throws HereticusException {
		T parsed;
		try {
			parsed = GSON.fromJson(json, type);
		}
		catch (JsonParseException e) {
			throw new HereticusException("hereticus printed what is not its JSON: " +
				e.getMessage(), e);
		}
		if (parsed == null) {
			throw new HereticusException("hereticus printed nothing");
		}
		return parsed;
	}

	/** Fails when hereticus left out a field it always prints. */
	static <T> T required(T value, String field) throws HereticusException {
		if (value == null) {
			throw new HereticusException("the JSON of hereticus has no `" + field + "`");
		}
		return value;
	}
}
