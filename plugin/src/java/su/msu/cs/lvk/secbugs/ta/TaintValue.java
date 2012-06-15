package su.msu.cs.lvk.secbugs.ta;

import edu.umd.cs.findbugs.SourceLineAnnotation;

/**
 * Dataflow value representing tainted data.
 *
 * @author Igor Konnov
 */
public class TaintValue {
    public static final int TOP = -1;
    public static final int BOTTOM = -2;

    // for the moment UNTAINTED == DETAINTED, but in the future we can use it...
    public static final int DETAINTED = 1;
    public static final int UNTAINTED = 1;
    public static final int TAINTED = 2;

    public static final TaintValue UNTAINTED_VALUE = new TaintValue(UNTAINTED, 0);

    // kind of tainted value: DETAINTED, UNTAINTED, or TAINTED
    private int kind;
    // depth of tainted value. Value of depth 0 was assigned by some tainted value of depth 0 directly.
    // Value of depth 1 received tainted value as a parameter of its method
    private int depth;

    /**
     * If value is tainted, then sourceLineAnnotation may point to the line from where tainted value is originating.
     */
    private SourceLineAnnotation sourceLineAnnotation;

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
        this.sourceLineAnnotation = source.sourceLineAnnotation;
    }

    public boolean isTop() {
        return this.kind == TOP;
    }

    public void copyFrom(TaintValue other) {
        this.kind = other.kind;
        this.depth = other.depth;
        this.sourceLineAnnotation = other.sourceLineAnnotation;
    }

    public void meetWith(TaintValue other) {
        if (other.kind == BOTTOM) {
            this.kind = BOTTOM;
            this.depth = 0;
            this.sourceLineAnnotation = null;
        }

        if (this.kind < other.kind) {
            this.kind = other.kind;
            this.depth = other.depth;
            this.sourceLineAnnotation = other.sourceLineAnnotation;
        } else if (this.kind == other.kind && this.kind == TAINTED) {
            this.depth = Math.min(this.depth, other.depth);
            if (this.sourceLineAnnotation == null) {
                this.sourceLineAnnotation = other.sourceLineAnnotation;
            } // else keep the old one
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

    public int getDepth() {
        return depth;
    }

    public void setDepth(int depth) {
        this.depth = depth;
    }

    public void increaseDepth() {
        if (kind == TAINTED) {
            this.depth++;
        }
    }

    public void decreaseDepth() {
        if (kind == TAINTED && depth > 0) {
            this.depth--;
        }
    }

    public SourceLineAnnotation getSourceLineAnnotation() {
        return sourceLineAnnotation;
    }

    public void setSourceLineAnnotation(SourceLineAnnotation sourceLineAnnotation) {
        this.sourceLineAnnotation = sourceLineAnnotation;
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

	
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		TaintValue other = (TaintValue) obj;
		if (depth != other.depth)
			return false;
		if (kind != other.kind)
			return false;
		return true;
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + depth;
		result = prime * result + kind;
		return result;
	}
    
}
