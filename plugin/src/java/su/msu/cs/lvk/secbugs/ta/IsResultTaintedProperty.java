package su.msu.cs.lvk.secbugs.ta;

/**
 * @author Igor Konnov
 */
public class IsResultTaintedProperty {
    private boolean tainted;

    public IsResultTaintedProperty() {
    }

    public IsResultTaintedProperty(boolean tainted) {
        this.tainted = tainted;
    }

    public boolean isTainted() {
        return tainted;
    }

    public void setTainted(boolean tainted) {
        this.tainted = tainted;
    }
}
