package su.msu.cs.lvk.secbugs.ta;

import edu.umd.cs.findbugs.SystemProperties;
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
import org.apache.bcel.generic.*;
import su.msu.cs.lvk.secbugs.bta.ParameterTaintnessProperty;
import su.msu.cs.lvk.secbugs.bta.ParameterTaintnessPropertyDatabase;
import su.msu.cs.lvk.secbugs.debug.DebugUtil;
import su.msu.cs.lvk.secbugs.util.HierarchyUtil;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

/**
 * Find sensitive parameters to which tainted data may be passed.
 *
 * @author Igor Konnov
 */
public class TaintUsageFinder {
    public static final boolean DEBUG_DUMP_DATAFLOW = SystemProperties.getBoolean("sec.ti.dump.dataflow");
    private ClassContext classContext;
    private Method method;
    private TaintUsageCollector collector;
    private TaintDataflow taintDataflow;
    private TypeDataflow typeDataflow;
    private IsResultTaintedPropertyDatabase isResultTaintedPropertyDatabase;
    private ParameterTaintnessPropertyDatabase parameterTaintnessPropertyDatabase;
    private List<Location> returnLocations;

    public TaintUsageFinder(ClassContext classContext, Method method, TaintUsageCollector collector) {
        this.classContext = classContext;
        this.method = method;
        this.collector = collector;
    }

    public void execute() {
        Profiler profiler = Global.getAnalysisCache().getProfiler();
        profiler.start(this.getClass());

        returnLocations = new ArrayList<Location>();
        try {
            // Get the TaintDataflow for the method from the ClassContext
            // ... and run analysis
            typeDataflow = classContext.getTypeDataflow(method);
            taintDataflow = getMethodAnalysis(TaintDataflow.class, method);
            checkAndSetDatabases();

            examineBasicBlocks();
            saveResultToDatabase();

            if (DEBUG_DUMP_DATAFLOW) {
                String path = DebugUtil.printDataflow(taintDataflow,
                        "ti_" + classContext.getJavaClass().getClassName() + "_" + method.getName());
                System.out.println("Dataflow of " + method + " dumped to " + path);
            }

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
        InvokeInstruction invokeInstruction = (InvokeInstruction) handle.getInstruction();
        ConstantPoolGen cpg = classContext.getConstantPoolGen();

        Collection<XMethod> calledMethods = HierarchyUtil.getResolvedMethods(typeFrame, invokeInstruction, cpg);
        for (XMethod xm : calledMethods) {
            checkCollisionWithSensitiveSink(location, xm);
        }
    }

    private void checkCollisionWithSensitiveSink(Location location, XMethod calledMethod) throws DataflowAnalysisException {
        TaintValueFrame fact = taintDataflow.getFactAtLocation(location);
        System.out.println("method "+ calledMethod.getName());
        System.out.println("fact "+fact.toString());
        ParameterTaintnessProperty property =
                parameterTaintnessPropertyDatabase.getProperty(calledMethod.getMethodDescriptor());
        if (property != null) {
            int numParams = calledMethod.getNumParams();
            for (int i = 0; i < numParams; ++i) {
                TaintValue value = fact.getStackValue(numParams - 1 - i);
                System.out.println(value);
                if (value.getKind() == TaintValue.TAINTED && property.isUntaint(i)) {
                    collector.foundTaintSensitiveParameter(classContext, location, value, property.getSinkSourceLine());
                }
            }
        }
    }

    private void saveResultToDatabase() throws DataflowAnalysisException {
        if (method.getReturnType() != Type.VOID) {
            // get previously saved (in examineBasicBlocks) return values and meet them
            XMethod xm = XFactory.createXMethod(classContext.getJavaClass(), method);
            IsResultTaintedProperty prop = isResultTaintedPropertyDatabase.getProperty(xm.getMethodDescriptor());
            if (prop == null) {
                throw new IllegalArgumentException("Called method " + xm
                        + " should be put to taintness database by MethodAnnotationDetector");
            }

            TaintValue result = prop.isTainted()
                    ? new TaintValue(TaintValue.TAINTED)
                    : new TaintValue(TaintValue.UNTAINTED);

            for (Location loc : returnLocations) {
                TaintValueFrame fact = taintDataflow.getFactAtLocation(loc);
                result.meetWith(fact.getTopValue());
            }

            prop = new IsResultTaintedProperty(result.getKind() == TaintValue.TAINTED);
            isResultTaintedPropertyDatabase.setProperty(xm.getMethodDescriptor(), prop);
        }
    }

    private void checkAndSetDatabases() throws CheckedAnalysisException {
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
