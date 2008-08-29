package su.msu.cs.lvk.secbugs.cases;

/**
 * @author Igor Konnov
 */
public class TaintedInterCase {
    private DataSource source = new DataSource();
    
    public void passTaintedValueToOtherClassMethod() {
        String tainted = source.getTaintedData("foo");
        TaintedCase taintedCase = new TaintedCase();
        taintedCase.interCallee(tainted);
    }

    public void passTaintedValueToOtherClassMethodTwoLevel() {
        String tainted = source.getTaintedData("foo");
        passTaintedValueToOtherClassMethodTwoLevelCallee(tainted);
    }

    private void passTaintedValueToOtherClassMethodTwoLevelCallee(String data) {
        TaintedCase taintedCase = new TaintedCase();
        taintedCase.interCallee(data);
    }
}
