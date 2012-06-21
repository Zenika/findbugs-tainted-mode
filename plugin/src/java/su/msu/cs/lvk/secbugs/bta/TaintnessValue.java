package su.msu.cs.lvk.secbugs.bta;

import edu.umd.cs.findbugs.SourceLineAnnotation;
import su.msu.cs.lvk.secbugs.ta.TaintValue;

/**
 * Dataflow value representing sensitive data, i.e. it can't be returned by tainted source.
 *
 * @author Igor Konnov
 */
public class TaintnessValue {
    public static final int BOTTOM_VALUE = 1;

    public static final int TAINTED_VALUE = 2;
    public static final int UNTAINTED_VALUE = 4;

    public static final TaintValue SENSITIVE_VALUE = new TaintValue();

    private int mask = TAINTED_VALUE;
    /**
     * Source line, where taint value is consumed.
     */
    private SourceLineAnnotation sinkSourceLine;

    public TaintnessValue() {
    }

    public TaintnessValue(TaintnessValue source) {
        this.mask = source.mask;
        this.sinkSourceLine = source.sinkSourceLine;
    }

    public void copyFrom(TaintnessValue other) {
        this.mask = other.mask;
        this.sinkSourceLine = other.sinkSourceLine;
    }

    public void meetWith(TaintnessValue other) {
        if ((other.mask & BOTTOM_VALUE) == BOTTOM_VALUE) {
            this.mask = BOTTOM_VALUE;
            this.sinkSourceLine = null;
        }

        this.mask |= other.mask;

        if (this.sinkSourceLine == null) {
            this.sinkSourceLine = other.sinkSourceLine;
        } // else keep the first source line
    }

    public static TaintnessValue merge(TaintnessValue a, TaintnessValue b) {
        TaintnessValue result = new TaintnessValue(a);
        result.meetWith(b);
        return result;
    }

    public boolean sameAs(TaintnessValue other) {
        return this.mask == other.mask;
    }

    public void setTainted(boolean tainted) {
        if (tainted) {
            mask |= TAINTED_VALUE;
        } else {
            mask &= ~TAINTED_VALUE;
        }
    }

    public boolean getTainted() {
        return (mask & TAINTED_VALUE) != 0;
    }

    public void setUntainted(boolean untainted) {
        if (untainted) {
            mask |= UNTAINTED_VALUE;
        } else {
            mask &= ~UNTAINTED_VALUE;
        }
    }

    public boolean getUntainted() {
        return (mask & UNTAINTED_VALUE) != 0;
    }

    public SourceLineAnnotation getSinkSourceLine() {
        return sinkSourceLine;
    }

    public void setSinkSourceLine(SourceLineAnnotation sinkSourceLine) {
        this.sinkSourceLine = sinkSourceLine;
    }

    public String toString() {
        if (getTainted()) {
            if (getUntainted()) {
                return "X";
            } else {
                return "T";
            }
        } else if (getUntainted()) {
            return "U";
        } else {
            return "?";
        }
    }

    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        TaintnessValue that = (TaintnessValue) o;

        return mask == that.mask;
    }

    public int hashCode() {
        return mask;
    }
}