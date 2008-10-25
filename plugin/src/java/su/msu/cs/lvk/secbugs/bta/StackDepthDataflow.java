package su.msu.cs.lvk.secbugs.bta;

import edu.umd.cs.findbugs.ba.AbstractDataflow;
import edu.umd.cs.findbugs.ba.CFG;
import edu.umd.cs.findbugs.ba.StackDepth;
import su.msu.cs.lvk.secbugs.bta.StackDepthAnalysis2;

/**
 * @author Igor Konnov
 */
public class StackDepthDataflow extends AbstractDataflow<StackDepth, StackDepthAnalysis2> {
    public StackDepthDataflow(CFG cfg, StackDepthAnalysis2 analysis) {
        super(cfg, analysis);
    }

    
}
