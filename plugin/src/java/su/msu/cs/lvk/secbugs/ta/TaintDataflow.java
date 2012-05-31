package su.msu.cs.lvk.secbugs.ta;

import edu.umd.cs.findbugs.ba.AbstractDataflow;
import edu.umd.cs.findbugs.ba.CFG;
import edu.umd.cs.findbugs.ba.Edge;
import edu.umd.cs.findbugs.ba.DataflowAnalysisException;

/**
 * @author Igor Konnov
 */
public class TaintDataflow extends AbstractDataflow<TaintValueFrame, TaintAnalysis> {
    public TaintDataflow(CFG cfg, TaintAnalysis analysis) {
        super(cfg, analysis);
    }

    public TaintValueFrame getFactAtMidEdge(Edge edge) throws DataflowAnalysisException {
        return getAnalysis().getFactAtMidEdge(edge);
    }

}
