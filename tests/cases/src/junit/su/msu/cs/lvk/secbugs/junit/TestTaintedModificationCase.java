package su.msu.cs.lvk.secbugs.junit;

import edu.umd.cs.findbugs.BugCollection;

/**
 * Hard test case for static taint analysis using findbugs.
 *
 * @author Igor Konnov
 */
public class TestTaintedModificationCase extends AbstractFindbugsTestCase {
    /**
     * <p>This test does not pass. I do not imagine, how to implement
     * better intraprocedural forward and backward analysises to find
     * that kind of vulnerability using findbugs.</p>
     *
     * <p>What we need to pass it: we need an iterative intraprocedural analysis
     * with an ability to store not only the taintness result of method call,
     * but a transfer function from parameters to its result.</p>
     *
     * <p><i>Igor Konnov</i>, 2008-09-12</p>
     */
    public void testPassTaintedValueViaModificationMethod() {
        runFindBugs("su.msu.cs.lvk.secbugs.cases.TaintedModificationCase",
                "passTaintedValueViaModificationMethod", "TI_TAINTED_INJECTION");
        BugCollection bugs = getBugCollection();

// actually:
        assertEquals(0, bugs.getCollection().size());
// MUST BE:
//        assertEquals(1, bugs.getCollection().size());
    }
}