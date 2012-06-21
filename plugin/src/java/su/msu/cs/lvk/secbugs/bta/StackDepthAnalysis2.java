package su.msu.cs.lvk.secbugs.bta;

import edu.umd.cs.findbugs.ba.*;
import org.apache.bcel.Constants;
import org.apache.bcel.generic.ConstantPoolGen;
import org.apache.bcel.generic.Instruction;
import org.apache.bcel.generic.InstructionHandle;

/**
 * Improved version of StackDepthAnalysis, handles catch blocks correctly.
 *
 * @author Igor Konnov
 * @ses edu.umd.cs.findbugs.ba.StackDepthAnalysis
 */
public class StackDepthAnalysis2 extends ForwardDataflowAnalysis<StackDepth> {
    public static final int TOP = -1;
    public static final int BOTTOM = -2;

    private ConstantPoolGen cpg;

    /**
     * Constructor.
     *
     * @param cpg the ConstantPoolGen of the method whose CFG we're performing the analysis on
     * @param dfs DepthFirstSearch of the method's CFG
     */
    public StackDepthAnalysis2(ConstantPoolGen cpg, DepthFirstSearch dfs) {
        super(dfs);
        this.cpg = cpg;
    }

    public StackDepth createFact() {
        return new StackDepth(TOP);
    }

    public void makeFactTop(StackDepth fact) {
        fact.setDepth(TOP);
    }

    public boolean isTop(StackDepth fact) {
        return fact.getDepth() == TOP;
    }

    @Override
    public boolean isFactValid(StackDepth fact) {
        int depth = fact.getDepth();
        return depth != TOP && depth != BOTTOM;
    }

    public void copy(StackDepth source, StackDepth dest) {
        dest.setDepth(source.getDepth());
    }

    public void initEntryFact(StackDepth entryFact) {
        entryFact.setDepth(0); // stack depth == 0 at entry to CFG
    }

    public boolean same(StackDepth fact1, StackDepth fact2) {
        return fact1.getDepth() == fact2.getDepth();
    }

    @Override
    public void transferInstruction(InstructionHandle handle, BasicBlock basicBlock, StackDepth fact) throws DataflowAnalysisException {
        Instruction ins = handle.getInstruction();
        int produced = ins.produceStack(cpg);
        int consumed = ins.consumeStack(cpg);
        if (produced == Constants.UNPREDICTABLE || consumed == Constants.UNPREDICTABLE)
            throw new IllegalStateException("Unpredictable stack delta for instruction: " + handle);
        int depth = fact.getDepth();
        depth += (produced - consumed);
        if (depth < 0)
            fact.setDepth(BOTTOM);
        else
            fact.setDepth(depth);
    }

    public void meetInto(StackDepth fact, Edge edge, StackDepth result) {
        if (fact.getDepth() != BOTTOM && fact.getDepth() != TOP
                && (edge.getType() == Edge.HANDLED_EXCEPTION_EDGE
                || edge.getType() == Edge.UNHANDLED_EXCEPTION_EDGE)) {
            // exception reference is held on the stack
            result.setDepth(1);
        } else {
            // normal meet
            int a = fact.getDepth();
            int b = result.getDepth();
            int combined;

            if (a == TOP)
                combined = b;
            else if (b == TOP)
                combined = a;
            else if (a == BOTTOM || b == BOTTOM || a != b)
                combined = BOTTOM;
            else
                combined = a;

            result.setDepth(combined);
        }
    }
}
