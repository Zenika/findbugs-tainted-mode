package su.msu.cs.lvk.secbugs.bta;

import edu.umd.cs.findbugs.ba.*;
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import edu.umd.cs.findbugs.classfile.IAnalysisCache;
import edu.umd.cs.findbugs.classfile.MethodDescriptor;
import edu.umd.cs.findbugs.classfile.engine.bcel.AnalysisFactory;
import org.apache.bcel.generic.MethodGen;

/**
 * @author Igor Konnov
 */
public class TaintnessDataflowFactory extends AnalysisFactory<TaintnessDataflow> {
    public TaintnessDataflowFactory() {
        super("taintness analysis", TaintnessDataflow.class);
    }

    public TaintnessDataflow analyze(IAnalysisCache analysisCache, MethodDescriptor descriptor) throws CheckedAnalysisException {
        MethodGen methodGen = getMethodGen(analysisCache, descriptor);
        if (methodGen == null) {
            throw new MethodUnprofitableException(descriptor);
        }
        CFG cfg = getCFG(analysisCache, descriptor);
        DepthFirstSearch dfs = getDepthFirstSearch(analysisCache, descriptor);
        ReverseDepthFirstSearch rdfs = getReverseDepthFirstSearch(analysisCache, descriptor);


        JavaClassAndMethod javaClassAndMethod = new JavaClassAndMethod(
                getJavaClass(analysisCache, descriptor.getClassDescriptor()),
                getMethod(analysisCache, descriptor));
        TaintnessAnalysis taintnessAnalysis = new TaintnessAnalysis(methodGen, cfg, rdfs, dfs, javaClassAndMethod);

        TaintnessDataflow taintnessDataflow = new TaintnessDataflow(cfg, taintnessAnalysis);
        taintnessDataflow.execute();
        if (ClassContext.DUMP_DATAFLOW_ANALYSIS) {
            taintnessDataflow.dumpDataflow(taintnessAnalysis);
        }
        return taintnessDataflow;
    }
}