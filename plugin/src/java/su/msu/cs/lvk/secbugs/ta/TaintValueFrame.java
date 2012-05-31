package su.msu.cs.lvk.secbugs.ta;

import edu.umd.cs.findbugs.ba.DataflowAnalysisException;
import edu.umd.cs.findbugs.ba.Frame;

import java.util.ArrayList;
import java.util.List;

/**
 * @author Igor Konnov
 */
public class TaintValueFrame extends Frame<TaintValue> {
    // track what locals were directly loaded on stack
    private List<Integer> localSources = new ArrayList<Integer>();

    public TaintValueFrame(int numLocals) {
        super(numLocals);
    }

    public void clearStack() {
        super.clearStack();
        localSources.clear();
    }

    public void copyFrom(Frame<TaintValue> other) {
        super.copyFrom(other);

        localSources = new ArrayList<Integer>(((TaintValueFrame) other).localSources);
    }

    public void pushValue(TaintValue value) {
        super.pushValue(value);
        localSources.add(-1); // by default, source index is unknown
    }

    public TaintValue popValue() throws DataflowAnalysisException {
        TaintValue value = super.popValue();
        localSources.remove(localSources.size() - 1);

        return value;
    }

    public void setTopStackValueSourceIndex(int localIndex) {
        localSources.set(localSources.size() - 1, localIndex);
    }

    public void setStackValueSourceIndex(int loc, int localIndex) {
        int size = localSources.size();
        if (loc >= size) {
            throw new IllegalStateException(
                    "not enough values on stack: access=" + loc + ", avail=" + size);
        }
        
        localSources.set(size - (loc + 1), localIndex);
    }

    public int getStackValueSourceIndex(int loc) {
        int size = localSources.size();
        if (loc >= size) {
            throw new IllegalStateException(
                    "not enough values on stack: access=" + loc + ", avail=" + size);
        }

        return localSources.get(size - (loc + 1));
    }
}
