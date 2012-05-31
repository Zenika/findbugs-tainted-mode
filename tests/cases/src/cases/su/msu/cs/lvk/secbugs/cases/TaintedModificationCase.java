package su.msu.cs.lvk.secbugs.cases;

/**
 * This is actually a hard-case for our detectors.
 * I do not know how to propagate such a taintness in findbugs.
 *
 * @author Igor Konnov
 */
public class TaintedModificationCase {
    private DataSource source = new DataSource();

    public void passTaintedValueViaModificationMethod() {
        String tainted = source.getTaintedData("foo");
        String modified = modifyTainted(tainted);
        TaintedCase taintedCase = new TaintedCase();
        taintedCase.interCallee(modified);
    }

    private String modifyTainted(String tainted) {
        return tainted;
    }
}
