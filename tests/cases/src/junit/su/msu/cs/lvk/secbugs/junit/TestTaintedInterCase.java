package su.msu.cs.lvk.secbugs.junit;

import edu.umd.cs.findbugs.BugCollection;

/**
 * @author Igor Konnov
 */
public class TestTaintedInterCase extends AbstractFindbugsTestCase {
    public void testInterCallee() {
        runFindBugs("su.msu.cs.lvk.secbugs.cases.TaintedCase", "interCaller", "TI_TAINTED_INJECTION");
        BugCollection bugs = getBugCollection();
        assertEquals(1, bugs.getCollection().size());
    }

    public void testPassTaintedValueToOtherClassMethod() {
        runFindBugs("su.msu.cs.lvk.secbugs.cases.TaintedInterCase",
                "passTaintedValueToOtherClassMethod", "TI_TAINTED_INJECTION");
        BugCollection bugs = getBugCollection();
        assertEquals(1, bugs.getCollection().size());
    }

    public void testPassTaintedValueToOtherClassMethodTwoLevel1() {
        runFindBugs("su.msu.cs.lvk.secbugs.cases.TaintedInterCase",
                "passTaintedValueToOtherClassMethodTwoLevel", "TI_TAINTED_INJECTION");
        BugCollection bugs = getBugCollection();
        assertEquals(1, bugs.getCollection().size());
    }
}
