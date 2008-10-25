package su.msu.cs.lvk.secbugs.bta;

import edu.umd.cs.findbugs.ba.CFG;
import edu.umd.cs.findbugs.ba.ClassContext;
import edu.umd.cs.findbugs.ba.DepthFirstSearch;
import edu.umd.cs.findbugs.ba.MethodUnprofitableException;
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import edu.umd.cs.findbugs.classfile.IAnalysisCache;
import edu.umd.cs.findbugs.classfile.MethodDescriptor;
import edu.umd.cs.findbugs.classfile.engine.bcel.AnalysisFactory;
import org.apache.bcel.generic.MethodGen;

/**
 * @author Igor Konnov
 */
public class StackDepthDataflowFactory extends AnalysisFactory<StackDepthDataflow> {
    public StackDepthDataflowFactory() {
        super("stack depth analysis", StackDepthDataflow.class);
    }

    public StackDepthDataflow analyze(IAnalysisCache analysisCache, MethodDescriptor descriptor) throws CheckedAnalysisException {
        MethodGen methodGen = getMethodGen(analysisCache, descriptor);
        if (methodGen == null) {
            throw new MethodUnprofitableException(descriptor);
        }

        CFG cfg = getCFG(analysisCache, descriptor);
        DepthFirstSearch dfs = getDepthFirstSearch(analysisCache, descriptor);

        StackDepthAnalysis2 stackDepthAnalysis = new StackDepthAnalysis2(methodGen.getConstantPool(), dfs);

        StackDepthDataflow stackDepthDataflow = new StackDepthDataflow(cfg, stackDepthAnalysis);
        stackDepthDataflow.execute();
        if (ClassContext.DUMP_DATAFLOW_ANALYSIS) {
            stackDepthDataflow.dumpDataflow(stackDepthAnalysis);
        }
        return stackDepthDataflow;
    }

}
