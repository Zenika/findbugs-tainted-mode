package su.msu.cs.lvk.secbugs.ta;

import edu.umd.cs.findbugs.ba.*;
import edu.umd.cs.findbugs.ba.type.TypeDataflow;
import edu.umd.cs.findbugs.ba.type.TypeFrame;
import edu.umd.cs.findbugs.bcel.BCELUtil;
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import edu.umd.cs.findbugs.classfile.Global;
import edu.umd.cs.findbugs.classfile.MethodDescriptor;
import edu.umd.cs.findbugs.log.Profiler;
import org.apache.bcel.Constants;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.Instruction;
import org.apache.bcel.generic.InstructionHandle;
import org.apache.bcel.generic.InvokeInstruction;
import org.apache.bcel.generic.Type;
import su.msu.cs.lvk.secbugs.bta.ParameterTaintnessProperty;
import su.msu.cs.lvk.secbugs.bta.ParameterTaintnessPropertyDatabase;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * Find sensitive parameters to which tainted data may be passed.
 *
 * @author Igor Konnov
 */
public class TaintUsageFinder {
    private ClassContext classContext;
    private Method method;
    private TaintUsageCollector collector;
    private TaintDataflow taintDataflow;
    private TypeDataflow typeDataflow;
    private IsParameterTaintedPropertyDatabase isParamTaintedPropertyDatabase;
    private IsResultTaintedPropertyDatabase isResultTaintedPropertyDatabase;
    private ParameterTaintnessPropertyDatabase parameterTaintnessPropertyDatabase;
    private List<Location> returnLocations;

    public TaintUsageFinder(ClassContext classContext, Method method, TaintUsageCollector collector) {
        this.classContext = classContext;
        this.method = method;
        this.collector = collector;
    }

    public void execute() {
        Profiler profiler = Profiler.getInstance();
        profiler.start(this.getClass());

        returnLocations = new ArrayList<Location>();        
        try {
            // Get the TaintDataflow for the method from the ClassContext
            // ... and run analysis
            taintDataflow = getMethodAnalysis(TaintDataflow.class, method);
            typeDataflow = classContext.getTypeDataflow(method);
            checkAndSetDatabases();

            examineBasicBlocks();
            saveResultToDatabase();
        } catch (DataflowAnalysisException e) {
            AnalysisContext.logError("Error while getting taint analysis dataflow in " +
                    method.getName(), e);
        } catch (CFGBuilderException e) {
            AnalysisContext.logError("Error while looking for tainted parameters in " +
                    method.getName(), e);
        } catch (ClassNotFoundException e) {
            AnalysisContext.logError("Class not found.", e);
        } catch (CheckedAnalysisException e) {
            AnalysisContext.logError("Analysis exception.", e);
        } finally {
            profiler.end(this.getClass());
        }
    }

    private void examineBasicBlocks() throws DataflowAnalysisException, ClassNotFoundException {
        Iterator<BasicBlock> bbIter = taintDataflow.getCFG().blockIterator();
        while (bbIter.hasNext()) {
            BasicBlock basicBlock = bbIter.next();

            if (!basicBlock.isEmpty()) {
                // Look for all instance calls to sensitive sinks
                //  with tainted parameters on stack
                BasicBlock.InstructionIterator insIter = basicBlock.instructionIterator();
                while (insIter.hasNext()) {
                    InstructionHandle handle = insIter.next();
                    if (isMethodInvocation(handle.getInstruction())) {
                        checkInvocation(basicBlock, handle);
                    }
                }

                InstructionHandle last = basicBlock.getLastInstruction();
                short opcode = last.getInstruction().getOpcode();
                switch (opcode) {
                    case Constants.ARETURN:
                    case Constants.IRETURN:
                    case Constants.LRETURN:
                    case Constants.FRETURN:
                    case Constants.DRETURN:
                        // any return of value
                        returnLocations.add(new Location(last, basicBlock));
                    default:
                        // do nothing
                }
            }
        }

    }

    private void checkInvocation(BasicBlock basicBlock, InstructionHandle handle) throws DataflowAnalysisException, ClassNotFoundException {
        Location location = new Location(handle, basicBlock);
        TypeFrame typeFrame = typeDataflow.getFactAtLocation(location);
        Set<JavaClassAndMethod> targetMethodSet = Hierarchy
                .resolveMethodCallTargets((InvokeInstruction) handle.getInstruction(), typeFrame, classContext.getConstantPoolGen());

        for (JavaClassAndMethod classAndMethod : targetMethodSet) {
            XMethod calledMethod = XFactory.createXMethod(classAndMethod);
            checkCollisionWithSensitiveSink(location, calledMethod);
//            saveTaintedParametersToDatabase(location, calledMethod);
        }
    }

    private void checkCollisionWithSensitiveSink(Location location, XMethod calledMethod) throws DataflowAnalysisException {
        TaintValueFrame fact = taintDataflow.getFactAtLocation(location);
        ParameterTaintnessProperty property =
                parameterTaintnessPropertyDatabase.getProperty(calledMethod.getMethodDescriptor());
        int numParams = calledMethod.getNumParams();
        for (int i = 0; i < numParams; ++i) {
            TaintValue value = fact.getStackValue(numParams - 1 - i);
            if (value.getKind() == TaintValue.TAINTED && property.isUntaint(i)) {
                collector.foundTaintSensitiveParameter(classContext, location, value);
            }
        }

/*
        for (int i = 0; i < calledMethod.getNumParams(); ++i) {
            XMethodParameter param = new XMethodParameter(calledMethod, i);
            TaintedAnnotation annotation = taintAnnotationDatabase.getResolvedAnnotation(param, false);
            TaintValue value = fact.getStackValue(i);
            if (annotation != null && annotation.equals(TaintedAnnotation.NEVER_TAINTED)
                    && value.getKind() == TaintValue.TAINTED) {
                // found it!
                collector.foundTaintSensitiveParameter(classContext, location, value);
            }
        }
*/
    }

    private TaintValue getResultFromAnnotation() {
        TaintedAnnotation annotation;
        TaintValue value;
        try {
            TaintAnnotationDatabase database = Global.getAnalysisCache().getDatabase(TaintAnnotationDatabase.class);
            XMethod xm = XFactory.createXMethod(classContext.getJavaClass(), method);
            annotation = database.getResolvedAnnotation(xm, false);
        } catch (CheckedAnalysisException e) {
            throw new RuntimeException("Error getting TaintAnnotationDatabase");
        }

        if (annotation != null) {
            if (TaintAnalysis.DEBUG) {
                System.out.println("Method " + method + " returns tainted data");
            }
            value = new TaintValue(TaintValue.TAINTED, 0);
        } else {
            value = new TaintValue(TaintValue.UNTAINTED);
        }

        return value;
    }

    private void saveResultToDatabase() throws DataflowAnalysisException {
        if (method.getReturnType() != Type.VOID) {
            // get previously saved (in examineBasicBlocks) return values and meet them
            TaintValue result = getResultFromAnnotation();
            for (Location loc : returnLocations) {
                TaintValueFrame fact = taintDataflow.getFactAtLocation(loc);
                result.meetWith(fact.getTopValue());
            }

            IsResultTaintedProperty prop = new IsResultTaintedProperty(result.getKind() == TaintValue.TAINTED);
            XMethod xm = XFactory.createXMethod(classContext.getJavaClass(), method);
            isResultTaintedPropertyDatabase.setProperty(xm.getMethodDescriptor(), prop);
        }
    }

    private void saveTaintedParametersToDatabase(Location location, XMethod calledMethod)
            throws DataflowAnalysisException {
        IsParameterTaintedProperty taintness = isParamTaintedPropertyDatabase.getProperty(calledMethod.getMethodDescriptor());
        if (taintness == null) {
            // nothing is tainted yet
            taintness = new IsParameterTaintedProperty();
        }

        TaintValueFrame fact = taintDataflow.getFactAtLocation(location);
        for (int i = 0; i < calledMethod.getNumParams(); ++i) {
            TaintValue value = fact.getStackValue(i);
            taintness.orUntaint(i, value.getKind() != TaintValue.TAINTED);
        }

        isParamTaintedPropertyDatabase.setProperty(calledMethod.getMethodDescriptor(), taintness);
    }

    private void checkAndSetDatabases() throws CheckedAnalysisException {
        isParamTaintedPropertyDatabase = Global.getAnalysisCache().getDatabase(IsParameterTaintedPropertyDatabase.class);
        isResultTaintedPropertyDatabase = Global.getAnalysisCache().getDatabase(IsResultTaintedPropertyDatabase.class);
        parameterTaintnessPropertyDatabase = Global.getAnalysisCache().getDatabase(ParameterTaintnessPropertyDatabase.class);
    }

    private boolean isMethodInvocation(Instruction instr) {
        return instr instanceof InvokeInstruction;
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

}
