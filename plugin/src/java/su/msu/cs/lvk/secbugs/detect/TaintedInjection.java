package su.msu.cs.lvk.secbugs.detect;

import edu.umd.cs.findbugs.BugInstance;
import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Detector;
import edu.umd.cs.findbugs.SystemProperties;
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import edu.umd.cs.findbugs.classfile.Global;
import edu.umd.cs.findbugs.ba.*;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.MethodGen;
import su.msu.cs.lvk.secbugs.ta.TaintAnnotationDatabase;
import su.msu.cs.lvk.secbugs.ta.TaintUsageCollector;
import su.msu.cs.lvk.secbugs.ta.TaintUsageFinder;
import su.msu.cs.lvk.secbugs.ta.TaintValue;
import su.msu.cs.lvk.secbugs.bta.ParameterTaintnessPropertyDatabase;

import java.util.List;

/**
 * @author Igor Konnov
 */
public class TaintedInjection implements Detector, TaintUsageCollector {
    public static final boolean DEBUG = SystemProperties.getBoolean("ti.debug");
    private BugReporter bugReporter;
    private ClassContext classContext;
    private Method method;
    private TaintAnnotationDatabase taintAnnotationDatabase;

    public TaintedInjection(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
    }

    public void visitClassContext(ClassContext classContext) {
        this.classContext = classContext;

        try {
            checkAndSetDatabases();
        } catch (CheckedAnalysisException e) {
            bugReporter.logError("While analyzing " + classContext.getClassDescriptor().getClassName()
                    + ": we caught cae exception", e);
        }

        String currentMethod = null;

        JavaClass jclass = classContext.getJavaClass();
        List<Method> methodList = classContext.getMethodsInCallOrder();
        for (Method method : methodList) {
            try {
                if (method.isAbstract() || method.isNative()
                        || method.getCode() == null) {
                    continue;
                }

                currentMethod = SignatureConverter.convertMethodSignature(jclass, method);

                if (DEBUG) {
                    System.out.println("Checking for TI in " + currentMethod);
                }

                analyzeMethod(classContext, method);
            } catch (MissingClassException e) {
                bugReporter.reportMissingClass(e.getClassNotFoundException());
            } catch (DataflowAnalysisException e) {
                bugReporter.logError("While analyzing " + currentMethod
                        + ": we caught dae exception", e);
            } catch (CFGBuilderException e) {
                bugReporter.logError("While analyzing " + currentMethod
                        + ": we caught cfgb exception", e);
            }

        }
    }

    private void analyzeMethod(ClassContext classContext, Method method)
            throws DataflowAnalysisException, CFGBuilderException {
        if (DEBUG) {
            System.out.println("Pre FND ");
        }

        MethodGen methodGen = classContext.getMethodGen(method);
        if (methodGen == null) {
            return;
        }

        /*
        if (!checkedDatabases) {
            checkDatabases();
            checkedDatabases = true;
        }
        */

        // UsagesRequiringNonNullValues uses =
        // classContext.getUsagesRequiringNonNullValues(method);
        this.method = method;

        if (DEBUG) {
            System.out.println("FND: "
                    + SignatureConverter.convertMethodSignature(methodGen));
        }

        // Create a TaintUsageFinder object to do the
        // actual work. It will call back to report usages of tainted data in sensitive sinks
        // comparisons through the TaintUsageCollector interface we implement.
        TaintUsageFinder worker = new TaintUsageFinder(classContext, method, this);
        worker.execute();
    }


    public void report() {
    }

    public void foundTaintSensitiveParameter(ClassContext classContext, Location location, TaintValue taintValue) {
        BugInstance bug = new BugInstance(this, "TI_TAINTED_INJECTION", Detector.NORMAL_PRIORITY);
        bug.addClassAndMethod(classContext.getJavaClass(), method);
        bug.addSourceLine(classContext, method, location).describe("TAINTED_PARAMETER");
        bugReporter.reportBug(bug);
    }

    private void checkAndSetDatabases() throws CheckedAnalysisException {
        taintAnnotationDatabase = Global.getAnalysisCache().getDatabase(TaintAnnotationDatabase.class);
    }

}
