package su.msu.cs.lvk.secbugs.ta;

import edu.umd.cs.findbugs.SystemProperties;
import edu.umd.cs.findbugs.ba.*;
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import edu.umd.cs.findbugs.classfile.Global;
import edu.umd.cs.findbugs.classfile.MethodDescriptor;
import org.apache.bcel.Constants;
import org.apache.bcel.generic.*;
import su.msu.cs.lvk.secbugs.ma.KeyIndicatorProperty;
import su.msu.cs.lvk.secbugs.ma.KeyIndicatorPropertyDatabase;

/**
 * @author Igor Konnov
 */
public class TaintAnalysis extends FrameDataflowAnalysis<TaintValue, TaintValueFrame> {
    static final boolean DEBUG = true; //SystemProperties.getBoolean("ta.debug");

    static {
        if (DEBUG) {
            System.out.println("ta.debug enabled");
        }
    }

    private MethodGen methodGen;
    private TaintValueFrameModelingVisitor visitor;

    private TaintValueFrame cachedEntryFact;
    private KeyIndicatorPropertyDatabase keyIndicatorPropertyDatabase;

    public TaintAnalysis(JavaClassAndMethod javaClassAndMethod, MethodGen methodGen, CFG cfg, DepthFirstSearch depthFirstSearch) throws CheckedAnalysisException {
        super(depthFirstSearch);
        this.methodGen = methodGen;
        this.visitor = new TaintValueFrameModelingVisitor(javaClassAndMethod,
                methodGen.getConstantPool());
        this.keyIndicatorPropertyDatabase = Global.getAnalysisCache().getDatabase(KeyIndicatorPropertyDatabase.class);
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
            
            int paramShift = instanceMethod ? 1 : 0;
            for (int i = 0; i < numLocals; ++i) {
                cachedEntryFact.setValue(i, new TaintValue(TaintValue.UNTAINTED));
            }
            if (paramShift == 1) {
                cachedEntryFact.setValue(0, new TaintValue(TaintValue.UNTAINTED));
            }
            
            Type[] argumentTypes = methodGen.getArgumentTypes();
            int slot = paramShift;
            for (Type argumentType : argumentTypes) {
                cachedEntryFact.setValue(slot, new TaintValue(TaintValue.UNTAINTED));

                slot += argumentType.getSize();
            }
            
            //test if method is main and mark arguments as tainted
            boolean isMainMethod = methodGen.isStatic() && methodGen.getName().equals("main") && methodGen.getSignature().equals("([Ljava/lang/String;)V");
            if(isMainMethod){
            	cachedEntryFact.setValue(0, new TaintValue(TaintValue.TAINTED,0));
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

                if (edgeType == Edge.IFCMP_EDGE || edgeType == Edge.FALL_THROUGH_EDGE) {
                    tmpFact = detaintIfValidated(sourceBlock, edgeType, fact);
                }
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

    private TaintValueFrame detaintIfValidated(BasicBlock sourceBlock, int edgeType, TaintValueFrame fact) throws DataflowAnalysisException {
        // call to validator looks like follows:
        // invokevirtual m
        // ifeq	n
        InstructionHandle last = sourceBlock.getLastInstruction();
        if (last != null) {
            InstructionHandle prev = last.getPrev();
            int opcode = last.getInstruction().getOpcode();

            if (edgeType == Edge.FALL_THROUGH_EDGE && opcode == Constants.IFEQ
                    || edgeType == Edge.IFCMP_EDGE && opcode == Constants.IFNE) {
                // It may be a call to validation method,
                // and current block is a then-branch
                if (prev != null && prev.getInstruction() instanceof InvokeInstruction) {
                    InvokeInstruction invoke = (InvokeInstruction) prev.getInstruction();
                    XMethod calledMethod = XFactory.createXMethod(invoke, methodGen.getConstantPool());

                    KeyIndicatorProperty prop = keyIndicatorPropertyDatabase.getProperty(calledMethod.getMethodDescriptor());
                    if (prop != null && prop.getIndicatorType() == KeyIndicatorProperty.IndicatorType.VALIDATOR) {
                        TaintValueFrame factBeforeCall = getFactAtLocation(new Location(prev, sourceBlock));
                        TaintValueFrame tmpFact = modifyFrame(fact, null);
                        for (int i = 0; i < calledMethod.getNumParams(); ++i) {
                            int sourceIndex = factBeforeCall.getStackValueSourceIndex(i);
                            if (sourceIndex != -1) {
                                // Parameter value is put on the stack by STORE instruction.
                                // Untaint local variable with source index.
                                tmpFact.setValue(sourceIndex, new TaintValue(TaintValue.DETAINTED));
                            }
                        }

                        return tmpFact;
                    }
                }
            }
        }

        return null;
    }
}
