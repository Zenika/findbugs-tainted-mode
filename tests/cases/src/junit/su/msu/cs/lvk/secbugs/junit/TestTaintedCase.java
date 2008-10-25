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

    public void testTaintedToInsensitive() {
        runFindBugs("su.msu.cs.lvk.secbugs.cases.TaintedCase", "taintedToInsensitive", "TI_TAINTED_INJECTION");
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

    public void testCallDirectly() {
        runFindBugs("su.msu.cs.lvk.secbugs.cases.TaintedCase", "callDirectly", "TI_TAINTED_INJECTION");
        BugCollection bugs = getBugCollection();
        assertEquals(1, bugs.getCollection().size());
    }

    public void testCallDirectlyWithAddition() {
        runFindBugs("su.msu.cs.lvk.secbugs.cases.TaintedCase", "callDirectlyWithAddition", "TI_TAINTED_INJECTION");
        BugCollection bugs = getBugCollection();
        assertEquals(1, bugs.getCollection().size());
    }

    public void testValidatorUntaintsOneBranch() {
        runFindBugs("su.msu.cs.lvk.secbugs.cases.TaintedCase", "validatorUntaintsOneBranch", "TI_TAINTED_INJECTION");
        BugCollection bugs = getBugCollection();
        assertEquals(0, bugs.getCollection().size());
    }

    public void testValidatorLeavesOtherBranchTainted() {
        runFindBugs("su.msu.cs.lvk.secbugs.cases.TaintedCase",
                "validatorLeavesOtherBranchTainted", "TI_TAINTED_INJECTION");
        BugCollection bugs = getBugCollection();
        assertEquals(1, bugs.getCollection().size());
    }

    public void testValidatorUntaintsOneBranchNeg() {
        runFindBugs("su.msu.cs.lvk.secbugs.cases.TaintedCase",
                "validatorUntaintsOneBranchNeg", "TI_TAINTED_INJECTION");
        BugCollection bugs = getBugCollection();
        assertEquals(0, bugs.getCollection().size());
    }

    public void testValidatorLeavesOtherBranchTaintedNeg() {
        runFindBugs("su.msu.cs.lvk.secbugs.cases.TaintedCase",
                "validatorLeavesOtherBranchTaintedNeg", "TI_TAINTED_INJECTION");
        BugCollection bugs = getBugCollection();
        assertEquals(1, bugs.getCollection().size());
    }

    public void testUntaintedMethodThrowsException() {
        runFindBugs("su.msu.cs.lvk.secbugs.cases.TaintedCase",
                "untaintedMethodThrowsException", "TI_TAINTED_INJECTION");
        BugCollection bugs = getBugCollection();
        assertEquals(0, bugs.getCollection().size());
    }

    public void testUntaintedMethodRethrowsException() {
        runFindBugs("su.msu.cs.lvk.secbugs.cases.TaintedCase",
                "untaintedMethodRethrowsException", "TI_TAINTED_INJECTION");
        BugCollection bugs = getBugCollection();
        assertEquals(0, bugs.getCollection().size());
    }

    public void testUntaintedMethodRethrowsExceptionWithFinally() {
        runFindBugs("su.msu.cs.lvk.secbugs.cases.TaintedCase",
                "untaintedMethodRethrowsExceptionWithFinally", "TI_TAINTED_INJECTION");
        BugCollection bugs = getBugCollection();
        assertEquals(0, bugs.getCollection().size());
    }
    
    public void testUntaintedMethodCatchesException() {
        runFindBugs("su.msu.cs.lvk.secbugs.cases.TaintedCase",
                "untaintedMethodCatchesException", "TI_TAINTED_INJECTION");
        BugCollection bugs = getBugCollection();
        assertEquals(0, bugs.getCollection().size());
    }

    public void testUntaintedMethodTryCatchFinallyThrows() {
        runFindBugs("su.msu.cs.lvk.secbugs.cases.TaintedCase",
                "untaintedMethodTryCatchFinallyThrows", "TI_TAINTED_INJECTION");
        BugCollection bugs = getBugCollection();
        assertEquals(0, bugs.getCollection().size());
    }
}
