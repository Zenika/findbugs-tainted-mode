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

        JavaClassAndMethod javaClassAndMethod;
        try {
            javaClassAndMethod = new JavaClassAndMethod(XFactory.createXMethod(descriptor));
        } catch (ClassNotFoundException e) {
            throw new CheckedAnalysisException("Can't construct javaClassAndMethod for " + descriptor, e);
        }
        TaintAnalysis taintAnalysis = new TaintAnalysis(javaClassAndMethod, methodGen, cfg, dfs);

        TaintDataflow taintDataflow = new TaintDataflow(cfg, taintAnalysis);
        try {
            taintDataflow.execute();
        } catch (AssertionError e) {
            // too many iterations assertion
            throw new CheckedAnalysisException("Assertion is not satisfied: " + e.getMessage());
        }
        if (ClassContext.DUMP_DATAFLOW_ANALYSIS) {
            taintDataflow.dumpDataflow(taintAnalysis);
        }
        return taintDataflow;
    }
}
