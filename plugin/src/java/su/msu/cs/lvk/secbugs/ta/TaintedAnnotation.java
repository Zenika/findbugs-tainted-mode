package su.msu.cs.lvk.secbugs.ta;

import edu.umd.cs.findbugs.ba.AnnotationEnumeration;

/**
 * @author Igor Konnov
 */
public class TaintedAnnotation extends AnnotationEnumeration<TaintedAnnotation> {
    public static final TaintedAnnotation UNKNOWN_TAINT_STATUS = new TaintedAnnotation("UnknownTaintStatus", 3);
    public static final TaintedAnnotation ALWAYS_TAINTED = new TaintedAnnotation("AlwaysTainted", 2);
    public static final TaintedAnnotation NEVER_TAINTED = new TaintedAnnotation("NeverTainted", 1);
    public static final TaintedAnnotation MAYBE_TAINTED = new TaintedAnnotation("MaybeTainted", 1);

    private final static TaintedAnnotation[] myValues = { UNKNOWN_TAINT_STATUS,
        ALWAYS_TAINTED, NEVER_TAINTED, MAYBE_TAINTED };

    protected TaintedAnnotation(String s, int i) {
        super(s, i);    //To change body of overridden methods use File | Settings | File Templates.
    }

    public String toString() {
        return super.toString();    //To change body of overridden methods use File | Settings | File Templates.
    }

    public static TaintedAnnotation[] values() {
        return myValues.clone();
    }

}
