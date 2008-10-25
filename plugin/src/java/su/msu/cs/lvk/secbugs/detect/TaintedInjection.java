package su.msu.cs.lvk.secbugs.detect;

import edu.umd.cs.findbugs.*;
import edu.umd.cs.findbugs.ba.*;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.MethodGen;
import su.msu.cs.lvk.secbugs.ta.TaintUsageCollector;
import su.msu.cs.lvk.secbugs.ta.TaintUsageFinder;
import su.msu.cs.lvk.secbugs.ta.TaintValue;

import java.util.List;

/**
 * @author Igor Konnov
 */
public class TaintedInjection implements Detector, TaintUsageCollector {
    public static final boolean DEBUG = SystemProperties.getBoolean("ti.debug");
    private BugReporter bugReporter;
    private Method method;

    public TaintedInjection(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
    }

    public void visitClassContext(ClassContext classContext) {
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

    public void foundTaintSensitiveParameter(ClassContext classContext, Location location,
                                             TaintValue taintValue, SourceLineAnnotation sinkSourceLine) {
        int prio = (taintValue.getDepth() == 0) ? Detector.NORMAL_PRIORITY : Detector.LOW_PRIORITY;

        BugInstance bug = new BugInstance(this, "TI_TAINTED_INJECTION", prio);
        bug.addClassAndMethod(classContext.getJavaClass(), method);
        bug.addSourceLine(classContext, method, location).describe("TAINTED_PARAMETER");
        if (taintValue.getSourceLineAnnotation() != null) {
            bug.add(taintValue.getSourceLineAnnotation()).describe("SOURCE_LINE_VALUE_SOURCE");
        }

        if (sinkSourceLine != null) {
            bug.add(sinkSourceLine).describe("SOURCE_LINE_VALUE_SINK");
        }
        
        bugReporter.reportBug(bug);
    }
}
