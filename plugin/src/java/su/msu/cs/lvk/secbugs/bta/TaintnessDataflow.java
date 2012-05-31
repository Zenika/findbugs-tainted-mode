package su.msu.cs.lvk.secbugs.bta;

import edu.umd.cs.findbugs.ba.AbstractDataflow;
import edu.umd.cs.findbugs.ba.CFG;
import edu.umd.cs.findbugs.ba.DataflowAnalysisException;
import edu.umd.cs.findbugs.ba.Edge;

/**
 * @author Igor Konnov
 */
public class TaintnessDataflow extends AbstractDataflow<TaintnessFrame, TaintnessAnalysis> {
    public TaintnessDataflow(CFG cfg, TaintnessAnalysis analysis) {
        super(cfg, analysis);
    }

    public TaintnessFrame getFactAtMidEdge(Edge edge) throws DataflowAnalysisException {
        return getAnalysis().getFactAtMidEdge(edge);
    }

}