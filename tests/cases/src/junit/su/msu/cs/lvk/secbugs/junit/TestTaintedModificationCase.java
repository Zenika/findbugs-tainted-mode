package su.msu.cs.lvk.secbugs.junit;

import edu.umd.cs.findbugs.BugCollection;

/**
 * @author Igor Konnov
 */
public class TestTaintedModificationCase extends AbstractFindbugsTestCase {
    public void testPassTaintedValueViaModificationMethod() {
        runFindBugs("su.msu.cs.lvk.secbugs.cases.TaintedModificationCase",
                "passTaintedValueViaModificationMethod", "TI_TAINTED_INJECTION");
        BugCollection bugs = getBugCollection();
        assertEquals(1, bugs.getCollection().size());
    }
}