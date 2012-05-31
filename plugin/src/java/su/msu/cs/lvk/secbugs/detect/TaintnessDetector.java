package su.msu.cs.lvk.secbugs.detect;

import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Detector;
import edu.umd.cs.findbugs.SystemProperties;
import edu.umd.cs.findbugs.ba.*;
import edu.umd.cs.findbugs.bcel.BCELUtil;
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import edu.umd.cs.findbugs.classfile.Global;
import edu.umd.cs.findbugs.classfile.MethodDescriptor;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.MethodGen;
import su.msu.cs.lvk.secbugs.bta.*;
import su.msu.cs.lvk.secbugs.debug.DebugUtil;
import su.msu.cs.lvk.secbugs.ta.TaintAnnotationDatabase;

import java.util.List;

/**
 * @author Igor Konnov
 */
public class TaintnessDetector implements Detector {
    public static final boolean DEBUG = true;//SystemProperties.getBoolean("sec.ta.debug");
    public static final boolean DEBUG_DUMP_DATAFLOW = false;//SystemProperties.getBoolean("sec.ta.dump.dataflow");

    private BugReporter bugReporter;
    private ClassContext classContext;
    private ParameterTaintnessPropertyDatabase taintnessPropertyDatabase;

    public TaintnessDetector(BugReporter bugReporter) {
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
                    System.out.println("Checking for taintness in " + currentMethod);
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

    private void checkAndSetDatabases() throws CheckedAnalysisException {
        taintnessPropertyDatabase = Global.getAnalysisCache().getDatabase(ParameterTaintnessPropertyDatabase.class);
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

        if (DEBUG) {
            System.out.println("FND: "
                    + SignatureConverter.convertMethodSignature(methodGen));
        }

        TaintnessDataflow dataflow = getMethodAnalysis(TaintnessDataflow.class, method);
        TaintnessFrame fact = dataflow.getResultFact(dataflow.getCFG().getEntry());

        if (DEBUG_DUMP_DATAFLOW) {
            String path = DebugUtil.printDataflow(dataflow,
                    "ta_" + classContext.getJavaClass().getClassName() + "_" + method.getName());
            System.out.println("Dataflow of " + method + " dumped to " + path);
        }
        try {
            // put taintness values of method parameters to property database
            putTaintnessProperty(classContext, method, fact);
        } catch (IllegalStateException e) {
            String path = DebugUtil.printDataflow(dataflow,
                    classContext.getJavaClass().getClassName() + "_" + method.getName());
            bugReporter.logError("Invalid fact met during taintness analysis of method " + method
                    + " dataflow saved to: " + path);
        }
    }

    private void putTaintnessProperty(ClassContext classContext, Method method, TaintnessFrame fact) {
        int shift = method.isStatic() ? 0 : 1;
        ParameterTaintnessProperty property = new ParameterTaintnessProperty();
        XMethod xmethod = XFactory.createXMethod(classContext.getJavaClass(), method);
        for (int i = 0; i < xmethod.getNumParams(); ++i) {
            TaintnessValue value = fact.getValue(shift + i);
            property.setTaint(i, value.getTainted());
            property.setUntaint(i, value.getUntainted());

            if (value.getSinkSourceLine() != null && property.getSinkSourceLine() == null) {
                property.setSinkSourceLine(value.getSinkSourceLine());
            }
        }

        ParameterTaintnessProperty oldProp = taintnessPropertyDatabase.getProperty(xmethod.getMethodDescriptor());
        if (oldProp != null) {
            oldProp.mergeWith(property);
        }

        if (DEBUG) {
            StringBuilder builder = new StringBuilder("Method ");
            builder.append(method.getName());
            builder.append(" taintness property: ");
            for (int i = 0; i < xmethod.getNumParams(); ++i) {
                TaintnessValue value = new TaintnessValue();
                value.setTainted(property.isTaint(i));
                value.setUntainted(property.isUntaint(i));
                builder.append(value.toString());
            }
            System.out.println(builder.toString());
        }
        taintnessPropertyDatabase.setProperty(xmethod.getMethodDescriptor(), property);
    }

    // copied from ClassContext, do not know, how to call this in other way
    private <Analysis> Analysis getMethodAnalysis(Class<Analysis> analysisClass, Method method)
            throws DataflowAnalysisException, CFGBuilderException {
        try {
            MethodDescriptor methodDescriptor =
                    BCELUtil.getMethodDescriptor(classContext.getJavaClass(), method);
            return Global.getAnalysisCache().getMethodAnalysis(analysisClass, methodDescriptor);
        } catch (CheckedAnalysisException e) {
            Throwable cause = e.getCause();
            if (cause instanceof CFGBuilderException) {
                throw (CFGBuilderException) cause;
            }
            System.out.println("Bad CAE: " + e.getClass().getName() + " for " + analysisClass.getName() + " of " + method);
            e.printStackTrace(System.out);
            IllegalStateException ise = new IllegalStateException("should not happen");
            ise.initCause(e);
            throw ise;
        }
    }

    public void report() {
    }
}