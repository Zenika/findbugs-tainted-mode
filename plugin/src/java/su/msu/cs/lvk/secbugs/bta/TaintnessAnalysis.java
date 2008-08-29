package su.msu.cs.lvk.secbugs.bta;

import edu.umd.cs.findbugs.SystemProperties;
import edu.umd.cs.findbugs.ba.*;
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import org.apache.bcel.generic.Instruction;
import org.apache.bcel.generic.InstructionHandle;
import org.apache.bcel.generic.MethodGen;
import org.apache.bcel.generic.Type;

/**
 * @author Igor Konnov
 */
public class TaintnessAnalysis extends BackwardFrameDataflowAnalysis<TaintnessValue, TaintnessFrame> {
    static final boolean DEBUG = SystemProperties.getBoolean("sec.ta.analysis.debug");

    static {
        if (DEBUG) {
            System.out.println("sec.ta.debug enabled");
        }
    }

    private MethodGen methodGen;
    private CFG cfg;
    private JavaClassAndMethod javaClassAndMethod;
    private TaintnessFrameModelingVisitor visitor;

    private TaintnessFrame cachedEntryFact;

    public TaintnessAnalysis(MethodGen methodGen, CFG cfg,
                             ReverseDepthFirstSearch rdfs, DepthFirstSearch dfs) throws CheckedAnalysisException {
        super(rdfs, dfs);
        this.methodGen = methodGen;
        this.cfg = cfg;
        this.visitor = new TaintnessFrameModelingVisitor(
                methodGen.getConstantPool());
    }

    public TaintnessFrame createFact() {
        return new TaintnessFrame(methodGen.getMaxLocals());
    }

    protected void mergeValues(TaintnessFrame otherFrame, TaintnessFrame resultFrame, int slot)
            throws DataflowAnalysisException {
        TaintnessValue value = TaintnessValue.merge(resultFrame.getValue(slot), otherFrame.getValue(slot));
        resultFrame.setValue(slot, value);
    }

    public void initEntryFact(TaintnessFrame result) throws DataflowAnalysisException {
        // copied from IsNullValueAnalysis
        if (cachedEntryFact == null) {
            cachedEntryFact = createFact();
            cachedEntryFact.setValid();

            int numLocals = methodGen.getMaxLocals();
            boolean instanceMethod = !methodGen.isStatic();
            XMethod xm = XFactory.createXMethod(methodGen.getClassName(),
                    methodGen.getName(), methodGen.getSignature(), methodGen.isStatic());

            int paramShift = instanceMethod ? 1 : 0;
            for (int i = 0; i < numLocals; ++i) {
                cachedEntryFact.setValue(i, new TaintnessValue());
            }
            if (paramShift == 1) {
                cachedEntryFact.setValue(0, new TaintnessValue());
            }

            Type[] argumentTypes = methodGen.getArgumentTypes();
            int slot = paramShift;
            for (int paramIndex = 0; paramIndex < argumentTypes.length; paramIndex++) {
                cachedEntryFact.setValue(slot, new TaintnessValue());

                slot += argumentTypes[paramIndex].getSize();
            }
        }
        copy(cachedEntryFact, result);
    }

    @Override
    public void transferInstruction(InstructionHandle handle, BasicBlock block, TaintnessFrame fact)
            throws DataflowAnalysisException {
        // Model the instruction
        Location loc = new Location(handle, block);
        visitor.setFrameAndLocation(fact, loc);
        Instruction ins = handle.getInstruction();
        if (DEBUG) {
            System.out.println("----> TrI " + ins + " at " + block);
        }
        visitor.analyzeInstruction(ins);
    }

    public void meetInto(TaintnessFrame fact, Edge edge, TaintnessFrame result) throws DataflowAnalysisException {
        // TODO: write it later
        meetInto(fact, edge, result, true);
    }

    public void meetInto(TaintnessFrame fact, Edge edge, TaintnessFrame result, boolean propagatePhiNodeInformation)
            throws DataflowAnalysisException {
        if (fact.isValid()) {
            TaintnessFrame tmpFact = null;

            final BasicBlock srcBlock = edge.getSource();

            if (srcBlock.isExceptionThrower()) {
                // Exception thrower - get identity
                if (result.isValid()) {
                    tmpFact = modifyFrame(result, tmpFact);
                }
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
    protected void mergeInto(TaintnessFrame other, TaintnessFrame result) throws DataflowAnalysisException {
        if (other.isTop()) return;
        if (result.isTop()) {
            result.copyFrom(other);
            return;
        }

        super.mergeInto(other, result);
    }

    public TaintnessFrame getFactAtMidEdge(Edge edge) throws DataflowAnalysisException {
        BasicBlock block = isForwards() ? edge.getSource() : edge.getTarget();

        TaintnessFrame predFact = createFact();
        copy(getResultFact(block), predFact);

        edgeTransfer(edge, predFact);

        TaintnessFrame result = createFact();
        makeFactTop(result);
        meetInto(predFact, edge, result, false);

        return result;
    }

    public void setClassAndMethod(JavaClassAndMethod javaClassAndMethod) {
        this.javaClassAndMethod = javaClassAndMethod;
    }
}