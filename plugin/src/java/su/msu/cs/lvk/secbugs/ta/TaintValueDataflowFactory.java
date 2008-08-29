package su.msu.cs.lvk.secbugs.ta;

import edu.umd.cs.findbugs.ba.*;
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import edu.umd.cs.findbugs.classfile.IAnalysisCache;
import edu.umd.cs.findbugs.classfile.MethodDescriptor;
import edu.umd.cs.findbugs.classfile.engine.bcel.AnalysisFactory;
import org.apache.bcel.generic.MethodGen;

/**
 * @author Igor Konnov
 */
public class TaintValueDataflowFactory extends AnalysisFactory<TaintDataflow> {
    public TaintValueDataflowFactory() {
        super("taint value analysis", TaintDataflow.class);
    }

    public TaintDataflow analyze(IAnalysisCache analysisCache, MethodDescriptor descriptor) throws CheckedAnalysisException {
        MethodGen methodGen = getMethodGen(analysisCache, descriptor);
        if (methodGen == null) {
            throw new MethodUnprofitableException(descriptor);
        }
        CFG cfg = getCFG(analysisCache, descriptor);
        DepthFirstSearch dfs = getDepthFirstSearch(analysisCache, descriptor);

        TaintAnalysis taintAnalysis = new TaintAnalysis(methodGen, cfg, dfs);

        // Set return value and parameter databases
        taintAnalysis.setClassAndMethod(new JavaClassAndMethod(
                getJavaClass(analysisCache, descriptor.getClassDescriptor()),
                getMethod(analysisCache, descriptor)));

        TaintDataflow taintDataflow = new TaintDataflow(cfg, taintAnalysis);
        taintDataflow.execute();
        if (ClassContext.DUMP_DATAFLOW_ANALYSIS) {
            taintDataflow.dumpDataflow(taintAnalysis);
        }
        return taintDataflow;
    }
}
