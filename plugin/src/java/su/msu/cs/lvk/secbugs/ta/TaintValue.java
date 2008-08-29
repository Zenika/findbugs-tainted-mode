package su.msu.cs.lvk.secbugs.ta;

/**
 * Dataflow value representing tainted data.
 *
 * @author Igor Konnov
 */
public class TaintValue {
    public static final int TOP = -1;
    public static final int BOTTOM = -2;

    public static final int DETAINTED = 1;
    public static final int UNTAINTED = 2;
    public static final int TAINTED = 3;

    public static final TaintValue UNTAINTED_VALUE = new TaintValue(UNTAINTED, 0);

    // kind of tainted value: DETAINTED, UNTAINTED, or TAINTED
    private int kind;
    // depth of tainted value. Value of depth 0 was assigned by some tainted value of depth 0 directly.
    // Value of depth 1 received tainted value as a parameter of its method
    private int depth;

    public TaintValue() {
        this.kind = TOP;
        this.depth = 0;
    }

    public TaintValue(int kind, int depth) {
        this.kind = kind;
        this.depth = depth;

        if (kind != TAINTED && depth != 0) {
            throw new IllegalArgumentException("Depth must have zero value if kind != TAINTED");
        }
    }

    public TaintValue(int kind) {
        this.kind = kind;
        this.depth = 0;
    }

    public TaintValue(TaintValue source) {
        this.kind = source.kind;
        this.depth = source.depth;
    }

    public boolean isTop() {
        return this.kind == TOP;
    }

    public void copyFrom(TaintValue other) {
        this.kind = other.kind;
        this.depth = other.depth;
    }

    public void meetWith(TaintValue other) {
        if (other.kind == BOTTOM) {
            this.kind = BOTTOM;
            this.depth = 0;
        }

        if (this.kind < other.kind) {
            this.kind = other.kind;
        } else if (this.kind == other.kind && this.kind == TAINTED) {
            this.depth = Math.min(this.depth, other.depth);
        }
    }

    public static TaintValue merge(TaintValue a, TaintValue b) {
        TaintValue result = new TaintValue(a);
        result.meetWith(b);
        return result;
    }

    public int getKind() {
        return kind;
    }

    public boolean sameAs(TaintValue other) {
        return this.kind == other.kind && this.depth == other.depth;
    }

    public String toString() {
        switch (kind) {
            case BOTTOM:
                return "BOT";
            case UNTAINTED:
                return "U";
            case TAINTED:
                return "T[" + depth + "]";
            default:
                return "TOP";
        }
    }
}
