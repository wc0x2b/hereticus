package hereticus;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class DiffReportTest {

	/** What `hereticus --format json --all` printed, cut to one pair. */
	private static final String REPORT = """
		{"pairs":[{"before":{"name":"sub_10","address":16},"after":{"name":"sub_20",\
		"address":32},"change":"changed","score":0.8125,"added":3,"removed":1,"edited":0,\
		"touched":{"branch":1},"matched_by":"similar"}],"gone":[{"function":{"name":"x",\
		"address":48},"holds":"code","closest":null,"in_place":null}],"new":[],\
		"totals":{"matched":1,"unchanged":0,"changed":1,"gone":1,"new":0}}""";

	@Test
	void readsEachPair() throws HereticusException {
		DiffReport report = DiffReport.parse(REPORT);
		assertEquals(1, report.pairs().size());
		DiffReport.Pair pair = report.pairs().get(0);
		assertEquals(16, pair.before().offset());
		assertEquals("sub_20", pair.after().name());
		assertEquals(32, pair.after().offset());
		assertEquals("changed", pair.change());
		assertEquals(0.8125, pair.score());
		assertEquals("similar", pair.matchedBy());
	}

	@Test
	void rejectsWhatIsNotAReport() {
		assertThrows(HereticusException.class, () -> DiffReport.parse("[]"));
		assertThrows(HereticusException.class, () -> DiffReport.parse("{\"gone\":[]}"));
		assertThrows(HereticusException.class,
			() -> DiffReport.parse(REPORT.replace("\"matched_by\":\"similar\"", "\"x\":1")));
		assertThrows(HereticusException.class,
			() -> DiffReport.parse(REPORT.replace("\"address\":32", "\"place\":32")));
	}
}
