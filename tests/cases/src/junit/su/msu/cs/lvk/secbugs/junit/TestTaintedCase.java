package su.msu.cs.lvk.secbugs.junit;

import edu.umd.cs.findbugs.BugCollection;

/**
 * Basic test of taint analysis. These tests are integration tests in fact, but JUnit provides
 * a convenient facility to run them.
 *
 * Beware: as for each test method distinguished firebugs process is run, the tests run slowly.
 *
 * @author Igor Konnov
 */
public class TestTaintedCase extends AbstractFindbugsTestCase {
    public void testUntainted() {
        runFindBugs("su.msu.cs.lvk.secbugs.cases.TaintedCase", "untainted", "TI_TAINTED_INJECTION");
        BugCollection bugs = getBugCollection();
        assertEquals(0, bugs.getCollection().size());
    }

    public void testOneBlock() {
        runFindBugs("su.msu.cs.lvk.secbugs.cases.TaintedCase", "oneBlock", "TI_TAINTED_INJECTION");
        BugCollection bugs = getBugCollection();
        assertEquals(1, bugs.getCollection().size());
    }

    public void testBranch() {
        runFindBugs("su.msu.cs.lvk.secbugs.cases.TaintedCase", "branch", "TI_TAINTED_INJECTION");
        BugCollection bugs = getBugCollection();
        assertEquals(1, bugs.getCollection().size());
    }

    public void testAssignment() {
        runFindBugs("su.msu.cs.lvk.secbugs.cases.TaintedCase", "assignment", "TI_TAINTED_INJECTION");
        BugCollection bugs = getBugCollection();
        assertEquals(1, bugs.getCollection().size());
    }
}
