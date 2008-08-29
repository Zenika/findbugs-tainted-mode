package su.msu.cs.lvk.secbugs.bta;

import edu.umd.cs.findbugs.ba.Frame;

/**
 * @author Igor Konnov
 */
public class TaintnessFrame extends Frame<TaintnessValue> {
    public TaintnessFrame(int numLocals) {
        super(numLocals);
    }
}
