package su.msu.cs.lvk.secbugs.ta;

import edu.umd.cs.findbugs.ba.Frame;

/**
 * @author Igor Konnov
 */
public class TaintValueFrame extends Frame<TaintValue> {
    public TaintValueFrame(int numLocals) {
        super(numLocals);
    }
}
