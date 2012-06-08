package su.msu.cs.lvk.secbugs.detect;

import edu.umd.cs.findbugs.*;
import edu.umd.cs.findbugs.ba.*;
import edu.umd.cs.findbugs.ba.type.TypeDataflow;
import edu.umd.cs.findbugs.ba.type.TypeFrame;
import edu.umd.cs.findbugs.bcel.CFGDetector;
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import edu.umd.cs.findbugs.classfile.Global;
import edu.umd.cs.findbugs.classfile.IAnalysisCache;
import edu.umd.cs.findbugs.classfile.MethodDescriptor;
import org.apache.bcel.generic.ConstantPoolGen;
import org.apache.bcel.generic.InstructionHandle;
import org.apache.bcel.generic.InvokeInstruction;
import su.msu.cs.lvk.secbugs.bta.ParameterTaintnessProperty;
import su.msu.cs.lvk.secbugs.bta.ParameterTaintnessPropertyDatabase;
import su.msu.cs.lvk.secbugs.ma.KeyIndicatorAnnotation;
import su.msu.cs.lvk.secbugs.ma.KeyIndicatorAnnotationDatabase;
import su.msu.cs.lvk.secbugs.ma.KeyIndicatorProperty;
import su.msu.cs.lvk.secbugs.ma.KeyIndicatorPropertyDatabase;
import su.msu.cs.lvk.secbugs.ta.IsResultTaintedProperty;
import su.msu.cs.lvk.secbugs.ta.IsResultTaintedPropertyDatabase;
import su.msu.cs.lvk.secbugs.ta.TaintAnnotationDatabase;
import su.msu.cs.lvk.secbugs.ta.TaintedAnnotation;
import su.msu.cs.lvk.secbugs.util.HierarchyUtil;

import java.util.Collection;
import java.util.Iterator;

/**
 * This detector finds taintness annotations of analyzed and called methods
 * and puts info about methods to databases.
 *
 * @author Igor Konnov
 */
public class MethodAnnotationDetector extends CFGDetector {
    public static final boolean DEBUG = SystemProperties.getBoolean("secbugs.mad.debug");

    private TaintAnnotationDatabase taintAnnotationDatabase;
    private KeyIndicatorAnnotationDatabase keyIndicatorAnnotationDatabase;
    private ParameterTaintnessPropertyDatabase parameterTaintnessPropertyDatabase;
    private IsResultTaintedPropertyDatabase isResultTaintedPropertyDatabase;
    private KeyIndicatorPropertyDatabase keyIndicatorPropertyDatabase;
    private BugReporter bugReporter;

    public MethodAnnotationDetector(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
    }

    public void report() {
    }

    protected void visitMethodCFG(MethodDescriptor methodDescriptor, CFG cfg) throws CheckedAnalysisException {
        if (DEBUG) {
            System.out.println("MethodAnnotationDetector: in " + methodDescriptor.getName());
        }

        checkAndSetDatabases();
        IAnalysisCache analysisCache = Global.getAnalysisCache();
        TypeDataflow typeDataflow = analysisCache.getMethodAnalysis(TypeDataflow.class, methodDescriptor);
        ConstantPoolGen cpg = analysisCache.getClassAnalysis(ConstantPoolGen.class, methodDescriptor.getClassDescriptor());

        XMethod caller = XFactory.createXMethod(methodDescriptor);
        checkAnnotations(null, null, caller);

        Iterator<BasicBlock> bbIter = cfg.blockIterator();
        while (bbIter.hasNext()) {
            BasicBlock basicBlock = bbIter.next();

            if (!basicBlock.isEmpty()) {
                // Look for all instance calls to sensitive sinks
                //  with tainted parameters on stack
                BasicBlock.InstructionIterator insIter = basicBlock.instructionIterator();
                while (insIter.hasNext()) {
                    InstructionHandle handle = insIter.next();
                    if (handle.getInstruction() instanceof InvokeInstruction) {
                        InvokeInstruction invoke = (InvokeInstruction) handle.getInstruction();

                        Location callLocation = new Location(handle, basicBlock);
                        TypeFrame typeFrame = typeDataflow.getFactAtLocation(callLocation);

                        try {
                            Collection<XMethod> methods = HierarchyUtil.getResolvedMethods(typeFrame, invoke, cpg);
                            for (XMethod xm : methods) {
                                checkAnnotations(caller, callLocation, xm);
                            }
                        } catch (ClassNotFoundException e) {
                            if (DEBUG) {
                                System.out.println("Class not found");
                            }
                            e.printStackTrace(System.err);
                        }
                    }
                }
            }
        }
    }

    private void checkAnnotations(XMethod caller, Location callLoc, XMethod callee) {
        checkIfResultTainted(caller, callLoc, callee);
        checkKeyIndicator(caller, callLoc, callee);
        checkParameterAnnotations(caller, callLoc, callee);
    }

    private void checkIfResultTainted(XMethod caller, Location callLoc, XMethod callee) {
        IsResultTaintedProperty property = isResultTaintedPropertyDatabase.getProperty(callee.getMethodDescriptor());
        if (property == null) {
            TaintedAnnotation annotation = taintAnnotationDatabase.getResolvedAnnotation(callee, false);
            if (annotation != null) {
                BugInstance bug = new BugInstance(this, "TI_DANGEROUS_POINT", Detector2.NORMAL_PRIORITY);
                bug.addClass(callee.getClassDescriptor());
                bug.addMethod(callee);
                bug.describe("Result of the method may be tainted");
                bugReporter.reportBug(bug);
            }

            property = new IsResultTaintedProperty(annotation != null);
            isResultTaintedPropertyDatabase.setProperty(callee.getMethodDescriptor(), property);
        }

        if (caller != null && callLoc != null && property.isTainted()) {
            BugInstance bug = new BugInstance(this, "TI_CALL_TAINTED_SOURCE", Detector2.NORMAL_PRIORITY);
            bug.addClass(caller.getClassDescriptor());
            bug.addMethod(caller);
            bug.addCalledMethod(callee.getClassName(), callee.getName(), callee.getSignature(), callee.isStatic());
            bug.addSourceLine(caller.getMethodDescriptor(), callLoc)
                    .describe("Potentially dangerous call to tainted data source");
            bugReporter.reportBug(bug);
        }
    }

    private void checkKeyIndicator(XMethod caller, Location callLoc, XMethod callee) {
        KeyIndicatorAnnotation annotation = keyIndicatorAnnotationDatabase.getResolvedAnnotation(callee, false);
        if (annotation != null) {
            if (caller != null && callLoc != null) {
                BugInstance bug = new BugInstance(this, "TI_CALL_KEY_INDICATOR", Detector2.NORMAL_PRIORITY);
                bug.addClass(caller.getClassDescriptor());
                bug.addMethod(caller);
                bug.addCalledMethod(callee.getClassName(), callee.getName(), callee.getSignature(), callee.isStatic());
                bug.addSourceLine(caller.getMethodDescriptor(), callLoc)
                        .describe("Call to a key indicator");
                bugReporter.reportBug(bug);
            }

            KeyIndicatorProperty property = keyIndicatorPropertyDatabase.getProperty(callee.getMethodDescriptor());

            if (property == null) {
                keyIndicatorPropertyDatabase.setProperty(callee.getMethodDescriptor(),
                        annotation.toKeyIndicatorProperty());

                BugInstance bug = new BugInstance(this, "TI_KEY_INDICATOR", Detector2.NORMAL_PRIORITY);
                bug.addClass(callee.getClassDescriptor());
                bug.addMethod(callee);
                bug.describe("Key indicator: " + annotation);
                bugReporter.reportBug(bug);
            }
        }
    }

    private void checkParameterAnnotations(XMethod caller, Location callLoc, XMethod callee) {
        ParameterTaintnessProperty prop = parameterTaintnessPropertyDatabase.getProperty(callee.getMethodDescriptor());
        
        if (prop == null) {
            // check for parameter annotations
            prop = new ParameterTaintnessProperty();
            for (int i = 0; i < callee.getNumParams(); ++i) {
                XMethodParameter param = new XMethodParameter(callee, i);
                TaintedAnnotation annotation = taintAnnotationDatabase.getResolvedAnnotation(param, false);
                if (annotation != null && annotation.equals(TaintedAnnotation.NEVER_TAINTED)) {
                    prop.setUntaint(i, true);
                    prop.setDirectSink(true);
                    reportSensitiveParameter(callee, i);
                } else {
                    prop.setTaint(i, true);
                }
            }

            if (DEBUG) {
                System.out.println("Method " + callee
                        + " added to parameterTaintnessPropertyDatabase (called from " + caller + ")");
            }
            // ...and put it to database
            parameterTaintnessPropertyDatabase.setProperty(callee.getMethodDescriptor(), prop);
        }

        if (caller != null && callLoc != null) {
            for (int i = 0; i < callee.getNumParams(); ++i) {
                if (prop.isUntaint(i)) {
                    BugInstance bug = new BugInstance(this, "TI_CALL_SENSITIVE_SINK", Detector2.NORMAL_PRIORITY);
                    bug.addClass(caller.getClassDescriptor());
                    bug.addMethod(caller);
                    bug.addCalledMethod(callee.getClassName(), callee.getName(), callee.getSignature(), callee.isStatic());
                    bug.addSourceLine(caller.getMethodDescriptor(), callLoc);
                    bug.describe("Call to method, which parameter " + i + " should be never tainted");
                    bugReporter.reportBug(bug);
                }
            }
        }
    }

    private void reportSensitiveParameter(XMethod method, int i) {
        BugInstance bug = new BugInstance(this, "TI_DANGEROUS_POINT", Detector2.NORMAL_PRIORITY);
        bug.addClass(method.getClassDescriptor());
        bug.addMethod(method);
        bug.describe("Parameter " + i + " should be never tainted");
        bugReporter.reportBug(bug);
    }

    private void checkAndSetDatabases() throws CheckedAnalysisException {
        if (keyIndicatorPropertyDatabase == null) {
            keyIndicatorPropertyDatabase = Global.getAnalysisCache().getDatabase(KeyIndicatorPropertyDatabase.class);
        }

        if (keyIndicatorAnnotationDatabase == null) {
            keyIndicatorAnnotationDatabase = Global.getAnalysisCache().getDatabase(KeyIndicatorAnnotationDatabase.class);
        }

        if (taintAnnotationDatabase == null) {
            taintAnnotationDatabase = Global.getAnalysisCache().getDatabase(TaintAnnotationDatabase.class);
        }

        if (parameterTaintnessPropertyDatabase == null) {
            parameterTaintnessPropertyDatabase = Global.getAnalysisCache().getDatabase(ParameterTaintnessPropertyDatabase.class);
        }

        if (isResultTaintedPropertyDatabase == null) {
            isResultTaintedPropertyDatabase = Global.getAnalysisCache().getDatabase(IsResultTaintedPropertyDatabase.class);
        }
    }
}
