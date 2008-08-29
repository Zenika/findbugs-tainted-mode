package su.msu.cs.lvk.secbugs.cases;

/**
 * Test cases of taint analysis.
 *
 * @author Igor Konnov
 */
public class TaintedCase {
    private DataSource source = new DataSource();
    private SensitiveSinks sinks = new SensitiveSinks();

    // parameter is untainted
    public void untainted() {
        String foo = source.getUntaintedData("foo");
        sinks.sensitive(foo);
    }

    // parameter is tainted in the basic block
    public void oneBlock() {
        String foo = source.getTaintedData("foo");
        sinks.sensitive(foo);
    }

    // parameter is tainted in one branch
    public void branch() {
        String tainted = source.getTaintedData("foo");
        String untainted = source.getUntaintedData("bar");

        if ("untainted".equals(untainted)) {
            sinks.sensitive(tainted);
        } else {
            sinks.insensitive(tainted);
        }
    }

    // parameter is tainted via assignment
    public void assignment() {
        String foo = source.getTaintedData("foo");
        String bar = foo;
        sinks.sensitive(bar);
    }

    public void interCaller() {
        String tainted = source.getTaintedData("foo");
        interCallee(tainted);
    }

    // parameter is tainted via call in interCaller
    public void interCallee(String tainted) {
        sinks.sensitive(tainted);
    }
}
