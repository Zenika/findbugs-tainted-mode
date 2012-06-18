package su.msu.cs.lvk.secbugs.bta;

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
public class TaintnessAnalysis extends BackwardFrameDataflowAnalysis<TaintnessValue, TaintnessFrame> {
    static final boolean DEBUG = SystemProperties.getBoolean("sec.ta.analysis.debug");

    static {
        if (DEBUG) {
            System.out.println("sec.ta.debug enabled");
        }
    }

    private MethodGen methodGen;
    private JavaClassAndMethod javaClassAndMethod;
    private TaintnessFrameModelingVisitor visitor;

    private TaintnessFrame cachedEntryFact;

    public TaintnessAnalysis(MethodGen methodGen, CFG cfg,
                             ReverseDepthFirstSearch rdfs, DepthFirstSearch dfs, JavaClassAndMethod javaClassAndMethod)
            throws CheckedAnalysisException {
        super(rdfs, dfs);
        this.methodGen = methodGen;
        this.javaClassAndMethod = javaClassAndMethod;
        this.visitor = new TaintnessFrameModelingVisitor(javaClassAndMethod,
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
        meetInto(fact, edge, result, true);
    }

    public void meetInto(TaintnessFrame fact, Edge edge, TaintnessFrame result, boolean propagatePhiNodeInformation)
            throws DataflowAnalysisException {
    	TaintnessFrame tmpFact = fact;
        if(fact.isValid()){	    	
	        if (edge.getSource().isExceptionThrower() && edge.getType() == EdgeTypes.UNHANDLED_EXCEPTION_EDGE
	                || edge.getType() == EdgeTypes.HANDLED_EXCEPTION_EDGE) {
	            // Exception thrower - restore operand stack
	            tmpFact = modifyFrame(fact, null);
	
	            XMethod method = XFactory.createXMethod(javaClassAndMethod);
	            try {
	                StackDepthDataflow dataflow = Global.getAnalysisCache()
	                        .getMethodAnalysis(StackDepthDataflow.class, method.getMethodDescriptor());
	                BasicBlock source = edge.getSource();
	                Location loc = new Location(source.getExceptionThrower(), source);
	                StackDepth depth = dataflow.getFactAtLocation(loc);
	                tmpFact.clearStack();
	                for (int i = 0; i < depth.getDepth(); ++i) {
	                    tmpFact.pushValue(new TaintnessValue());
	                }
	                if (DEBUG) {
	                    System.out.println("Edge transfer (ex thr) from "
	                            + edge.getSource() + " to " + edge.getTarget() + " -> " + fact);
	                }
	            } catch (CheckedAnalysisException e) {
	                throw new DataflowAnalysisException("Error handling throw block", e);
	            }
	        }
        }//if fact is valid
        
        mergeInto(tmpFact, result);
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
}