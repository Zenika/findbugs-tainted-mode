package su.msu.cs.lvk.secbugs.ta;

import java.util.BitSet;

/**
 * Property holding sensitive parameters of a method.
 * <p/>
 * Copied from edu.umd.cs.findbugs.ba.npe.ParamNullnessProperty.
 *
 * @author Igor Konnov
 */
public class IsParameterTaintedProperty {
    /**
     * Maximum number of parameters that can be represented by a IsParameterTaintedProperty.
     */
    public static final int MAX_PARAMS = 32;

    private int untaintParamSet;

    /**
     * Constructor.
     * Parameters are all assumed not to be untaint.
     */
    public IsParameterTaintedProperty() {
        this.untaintParamSet = 0;
    }

    /**
     * Get the untaint param bitset.
     *
     * @return the untaint param bitset
     */
    int getUntaintParamSet() {
        return untaintParamSet;
    }

    /**
     * Set the untaint param bitset.
     *
     * @param untaintParamSet the untaint param bitset
     */
    void setUntaintParamSet(int untaintParamSet) {
        this.untaintParamSet = untaintParamSet;
    }

    /**
     * Set the untaint param set from given BitSet.
     *
     * @param untaintSet BitSet indicating which parameters are
     *                    untaint
     */
    public void setUntaintParamSet(BitSet untaintSet) {
        for (int i = 0; i < 32; ++i) {
            setUntaint(i, untaintSet.get(i));
        }
    }

    /**
     * Set whether or not a parameter might be untaint.
     *
     * @param param    the parameter index
     * @param untaint true if the parameter might be untaint, false otherwise
     */
    public void setUntaint(int param, boolean untaint) {
        if (param < 0 || param > 31)
            return;
        if (untaint) {
            untaintParamSet |= (1 << param);
        } else {
            untaintParamSet &= ~(1 << param);
        }
    }

    /**
     * Add taintness to given parameter.
     *
     * @param param    the parameter index
     * @param untaint true if the parameter might be untaint, false otherwise
     */
    public void orUntaint(int param, boolean untaint) {
        if (param < 0 || param > 31)
            return;
        if (untaint) {
            untaintParamSet |= (1 << param);
        } // else it might be already taint or not 
    }

    /**
     * Return whether or not a parameter might be untaint.
     *
     * @param param the parameter index
     * @return true if the parameter might be untaint, false otherwise
     */
    public boolean isUntaint(int param) {
        if (param < 0 || param > 31)
            return false;
        else
            return (untaintParamSet & (1 << param)) != 0;
    }

    /**
     * Given a bitset of taint arguments passed to the method represented
     * by this property, return a bitset indicating which taint arguments
     * correspond to an untaint param.
     *
     * @param taintArgSet bitset of taint arguments
     * @return bitset intersecting taint arguments and untaint params
     */
    public BitSet getViolatedParamSet(BitSet taintArgSet) {
        BitSet result = new BitSet();
        for (int i = 0; i < 32; ++i) {
            result.set(i, taintArgSet.get(i) && isUntaint(i));
        }
        return result;
    }

    public BitSet getAsBitSet() {
        BitSet result = new BitSet();
        if (isEmpty()) return result;
        for (int i = 0; i < 32; ++i) {
            result.set(i, isUntaint(i));
        }
        return result;
    }

    /**
     * Return whether or not the set of untaint parameters
     * is empty.
     *
     * @return true if the set is empty, false if it contains at least one parameter
     */
    public boolean isEmpty() {
        return untaintParamSet == 0;
    }

    @Override
    public String toString() {
        StringBuffer buf = new StringBuffer();

        buf.append('{');
        for (int i = 0; i < 32; ++i) {
            if (isUntaint(i)) {
                if (buf.length() > 1)
                    buf.append(',');
                buf.append(i);
            }
        }
        buf.append('}');

        return buf.toString();
    }

    /**
     * Intersect this set with the given set.
     * Useful for summarizing the properties of multiple methods.
     *
     * @param targetDerefParamSet another set
     */
    public void intersectWith(IsParameterTaintedProperty targetDerefParamSet) {
        untaintParamSet &= targetDerefParamSet.untaintParamSet;
    }

    /**
     * Merge this set with the given set
     *
     * @param targetDerefParamSet another set
     */
    public void mergeWith(IsParameterTaintedProperty targetDerefParamSet) {
        untaintParamSet &= targetDerefParamSet.untaintParamSet;
    }

    /**
     * Make this object the same as the given one.
     *
     * @param other another IsParameterTaintedProperty
     */
    public void copyFrom(IsParameterTaintedProperty other) {
        this.untaintParamSet = other.untaintParamSet;
    }
}
