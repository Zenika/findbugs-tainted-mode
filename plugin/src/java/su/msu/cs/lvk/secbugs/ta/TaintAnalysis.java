package su.msu.cs.lvk.secbugs.ta;

import edu.umd.cs.findbugs.SystemProperties;
import edu.umd.cs.findbugs.ba.*;
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import edu.umd.cs.findbugs.classfile.Global;
import org.apache.bcel.generic.Instruction;
import org.apache.bcel.generic.InstructionHandle;
import org.apache.bcel.generic.MethodGen;
import org.apache.bcel.generic.Type;

/**
 * @author Igor Konnov
 */
public class TaintAnalysis extends FrameDataflowAnalysis<TaintValue, TaintValueFrame> {
    static final boolean DEBUG = SystemProperties.getBoolean("ta.debug");

    static {
        if (DEBUG) {
            System.out.println("ta.debug enabled");
        }
    }

    private MethodGen methodGen;
    private CFG cfg;
    private JavaClassAndMethod javaClassAndMethod;
    private TaintValueFrameModelingVisitor visitor;

    private TaintValueFrame cachedEntryFact;

    public TaintAnalysis(MethodGen methodGen, CFG cfg, DepthFirstSearch depthFirstSearch) {
        super(depthFirstSearch);
        this.methodGen = methodGen;
        this.cfg = cfg;
        this.visitor = new TaintValueFrameModelingVisitor(
                methodGen.getConstantPool());
    }

    public TaintValueFrame createFact() {
        return new TaintValueFrame(methodGen.getMaxLocals());
    }

    protected void mergeValues(TaintValueFrame otherFrame, TaintValueFrame resultFrame, int slot)
            throws DataflowAnalysisException {
        TaintValue value = TaintValue.merge(resultFrame.getValue(slot), otherFrame.getValue(slot));
        resultFrame.setValue(slot, value);
    }

    public void initEntryFact(TaintValueFrame result) throws DataflowAnalysisException {
        // copied from IsNullValueAnalysis
        if (cachedEntryFact == null) {
            cachedEntryFact = createFact();
            cachedEntryFact.setValid();

            int numLocals = methodGen.getMaxLocals();
            boolean instanceMethod = !methodGen.isStatic();
            XMethod xm = XFactory.createXMethod(methodGen.getClassName(),
                    methodGen.getName(), methodGen.getSignature(), methodGen.isStatic());
            IsParameterTaintedPropertyDatabase db;
            try {
                db = Global.getAnalysisCache().getDatabase(IsParameterTaintedPropertyDatabase.class);
            } catch (CheckedAnalysisException e) {
                throw new DataflowAnalysisException("Can't obtain parameter taintness database", e);
            }

            IsParameterTaintedProperty taintness = db.getProperty(xm.getMethodDescriptor());

            int paramShift = instanceMethod ? 1 : 0;
            for (int i = 0; i < numLocals; ++i) {
                cachedEntryFact.setValue(i, new TaintValue(TaintValue.UNTAINTED));
            }
            if (paramShift == 1) {
                cachedEntryFact.setValue(0, new TaintValue(TaintValue.UNTAINTED));
            }

            Type[] argumentTypes = methodGen.getArgumentTypes();
            int slot = paramShift;
            for (int paramIndex = 0; paramIndex < argumentTypes.length; paramIndex++) {
                if (taintness != null && !taintness.isUntaint(paramIndex)) {
                    cachedEntryFact.setValue(slot, new TaintValue(TaintValue.TAINTED));
                } else {
                    cachedEntryFact.setValue(slot, new TaintValue(TaintValue.UNTAINTED));
                }

                slot += argumentTypes[paramIndex].getSize();
            }
        }
        copy(cachedEntryFact, result);
    }

    @Override
    public void transferInstruction(InstructionHandle handle, BasicBlock block, TaintValueFrame fact)
            throws DataflowAnalysisException {
        // Model the instruction
        visitor.setFrameAndLocation(fact, new Location(handle, block));
        Instruction ins = handle.getInstruction();
        visitor.analyzeInstruction(ins);
    }

    public void meetInto(TaintValueFrame fact, Edge edge, TaintValueFrame result) throws DataflowAnalysisException {
        // TODO: write it later
        meetInto(fact, edge, result, true);
    }

    public void meetInto(TaintValueFrame fact, Edge edge, TaintValueFrame result, boolean propagatePhiNodeInformation)
            throws DataflowAnalysisException {
        if (fact.isValid()) {
            TaintValueFrame tmpFact = null;

            final BasicBlock destBlock = edge.getTarget();

            if (destBlock.isExceptionHandler()) {
                // Exception handler - clear stack and push a non-null value
                // to represent the exception.
                tmpFact = modifyFrame(fact, tmpFact);
                tmpFact.clearStack();

                // TODO: is it possible to throw tainted exception, e.g. an exception with a tainted message?

                // Push the exception value
                tmpFact.pushValue(TaintValue.UNTAINTED_VALUE);
            } else {
                final int edgeType = edge.getType();
                final BasicBlock sourceBlock = edge.getSource();
                final BasicBlock targetBlock = edge.getTarget();

                // TODO: it is a perfect place to check a validation expression!
                // If this is a fall-through edge from a null check,
                // then we know the value checked is not null.
                /*
                if (sourceBlock.isNullCheck() && edgeType == FALL_THROUGH_EDGE) {
                    ValueNumberFrame vnaFrame = vnaDataflow.getStartFact(destBlock);
                    if (vnaFrame == null)
                        throw new IllegalStateException("no vna frame at block entry?");

                    Instruction firstInDest = edge.getTarget().getFirstInstruction().getInstruction();


                    IsNullValue instance = fact.getInstance(firstInDest, methodGen.getConstantPool());


                    if (instance.isDefinitelyNull()) {
                        // If we know the variable is null, this edge is infeasible
                        tmpFact = createFact();
                        tmpFact.setTop();
                    } else if (!instance.isDefinitelyNotNull()) {
                        // If we're not sure that the instance is definitely non-null,
                        // update the is-null information for the dereferenced value.
                        InstructionHandle kaBoomLocation = targetBlock.getFirstInstruction();
                        ValueNumber replaceMe = vnaFrame.getInstance(firstInDest, methodGen.getConstantPool());
                        IsNullValue noKaboomNonNullValue = IsNullValue.noKaboomNonNullValue(
                                new Location(kaBoomLocation, targetBlock)
                        );
                        if (DEBUG) {
                            System.out.println("Start vna fact: " + vnaFrame);
                            System.out.println("inva fact: " + fact);
                            System.out.println("\nGenerated NoKaboom value for location " + kaBoomLocation);
                            System.out.println("Dereferenced " + instance);
                            System.out.println("On fall through from source block " + sourceBlock);
                        }
                        tmpFact = replaceValues(fact, tmpFact, replaceMe, vnaFrame, targetVnaFrame, noKaboomNonNullValue);
                    }
                } // if (sourceBlock.isNullCheck() && edgeType == FALL_THROUGH_EDGE)
                */
            }
            if (tmpFact != null) {
                fact = tmpFact;
            }
        } // if (fact.isValid())

        // Normal dataflow merge
        mergeInto(fact, result);
    }

    @Override
    protected void mergeInto(TaintValueFrame other, TaintValueFrame result) throws DataflowAnalysisException {
        if (other.isTop()) return;
        if (result.isTop()) {
            result.copyFrom(other);
            return;
        }

        super.mergeInto(other, result);
    }

    public TaintValueFrame getFactAtMidEdge(Edge edge) throws DataflowAnalysisException {
        BasicBlock block = isForwards() ? edge.getSource() : edge.getTarget();

        TaintValueFrame predFact = createFact();
        copy(getResultFact(block), predFact);

        edgeTransfer(edge, predFact);

        TaintValueFrame result = createFact();
        makeFactTop(result);
        meetInto(predFact, edge, result, false);

        return result;
    }

    public void setClassAndMethod(JavaClassAndMethod javaClassAndMethod) {
        this.javaClassAndMethod = javaClassAndMethod;
    }
}
