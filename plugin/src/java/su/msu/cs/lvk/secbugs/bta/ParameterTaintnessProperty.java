package su.msu.cs.lvk.secbugs.bta;

import edu.umd.cs.findbugs.SourceLineAnnotation;

import java.util.BitSet;

/**
 * Property holding sensitive parameters of a method.
 * <p/>
 * Copied from edu.umd.cs.findbugs.ba.npe.ParamNullnessProperty.
 *
 * @author Igor Konnov
 */
public class ParameterTaintnessProperty {
    /**
     * Maximum number of parameters that can be represented by a ParameterTaintnessProperty.
     */
    public static final int MAX_PARAMS = 32;

    // bit is set if parameter was required to be certainly tainted,
    private int paramTaintnessSet;
    // bit is set if parameter was required to be certainly untainted,
    private int paramUntaintnessSet;

    /**
     * Is it a direct sink?
     */
    private boolean directSink;

    /**
     * Optional source line, pointing to location, where taint value is consumed by a sensitive sink.
     */
    private SourceLineAnnotation sinkSourceLine;

    /**
     * Constructor.
     * Parameters are all assumed not to be untaint.
     */
    public ParameterTaintnessProperty() {
        this.paramTaintnessSet = 0;
        this.paramUntaintnessSet = 0;
    }

    /**
     * Get the taint param bitset.
     *
     * @return the taint param bitset
     */
    int getParamTaintnessSet() {
        return paramTaintnessSet;
    }

    /**
     * Set the taint param bitset.
     *
     * @param paramSet the untaint param bitset
     */
    void setParamTaintnessSet(int paramSet) {
        this.paramTaintnessSet = paramSet;
    }

    public int getParamUntaintnessSet() {
        return paramUntaintnessSet;
    }

    public void setParamUntaintnessSet(int paramUntaintnessSet) {
        this.paramUntaintnessSet = paramUntaintnessSet;
    }

    /**
     * Set the untaint param set from given BitSet.
     *
     * @param paramSet BitSet indicating which parameters are
     *                 untaint
     */
    public void setUntaintnessParamSet(BitSet paramSet) {
        for (int i = 0; i < 32; ++i) {
            setUntaint(i, paramSet.get(i));
        }
    }

    /**
     * Set the untaint param set from given BitSet.
     *
     * @param paramSet BitSet indicating which parameters are
     *                 untaint
     */
    public void setTaintnessParamSet(BitSet paramSet) {
        for (int i = 0; i < 32; ++i) {
            setTaint(i, paramSet.get(i));
        }
    }

    /**
     * Set whether or not a parameter might be untaint.
     *
     * @param param   the parameter index
     * @param untaint true if the parameter might be untaint, false otherwise
     */
    public void setUntaint(int param, boolean untaint) {
        if (param < 0 || param > 31)
            return;
        if (untaint) {
            paramUntaintnessSet |= (1 << param);
        } else {
            paramUntaintnessSet &= ~(1 << param);
        }
    }

    /**
     * Set whether or not a parameter might be untaint.
     *
     * @param param the parameter index
     * @param taint true if the parameter might be untaint, false otherwise
     */
    public void setTaint(int param, boolean taint) {
        if (param < 0 || param > 31)
            return;
        if (taint) {
            paramTaintnessSet |= (1 << param);
        } else {
            paramTaintnessSet &= ~(1 << param);
        }
    }

    /**
     * Add untaintness to given parameter.
     *
     * @param param   the parameter index
     * @param untaint true if the parameter might be untaint, false otherwise
     */
    public void orUntaint(int param, boolean untaint) {
        if (param < 0 || param > 31)
            return;
        if (untaint) {
            paramUntaintnessSet |= (1 << param);
        } // else it might be already taint or not
    }

    /**
     * Add taintness to given parameter.
     *
     * @param param the parameter index
     * @param taint true if the parameter might be untaint, false otherwise
     */
    public void orTaint(int param, boolean taint) {
        if (param < 0 || param > 31)
            return;
        if (taint) {
            paramTaintnessSet |= (1 << param);
        } // else it might be already taint or not
    }

    /**
     * Return whether or not a parameter might be untaint.
     *
     * @param param the parameter index
     * @return true if the parameter might be untaint, false otherwise
     */
    public boolean isUntaint(int param) {
        return !(param < 0 || param > 31) && (paramUntaintnessSet & (1 << param)) != 0;
    }

    /**
     * Return whether or not a parameter might be untaint.
     *
     * @param param the parameter index
     * @return true if the parameter might be untaint, false otherwise
     */
    public boolean isTaint(int param) {
        return !(param < 0 || param > 31) && (paramTaintnessSet & (1 << param)) != 0;
    }

    /**
     * Given a bitset of taint arguments passed to the method represented
     * by this property, return a bitset indicating which taint arguments
     * correspond to an untaint param.
     *
     * @return bitset intersecting taint arguments and untaint params
     */
    /*
    public BitSet getViolatedParamSet(BitSet taintArgSet) {
        BitSet result = new BitSet();
        for (int i = 0; i < 32; ++i) {
            result.set(i, taintArgSet.get(i) && isUntaint(i));
        }
        return result;
    }
    */
    public BitSet getTaintnessAsBitSet() {
        BitSet result = new BitSet();
        if (!hasTaint()) return result;
        for (int i = 0; i < 32; ++i) {
            result.set(i, isTaint(i));
        }
        return result;
    }

    public BitSet getUntaintnessAsBitSet() {
        BitSet result = new BitSet();
        if (!hasUntaint()) return result;
        for (int i = 0; i < 32; ++i) {
            result.set(i, isTaint(i));
        }
        return result;
    }

    /**
     * Return whether or not the set of untaint parameters
     * is empty.
     *
     * @return true if the set is empty, false if it contains at least one parameter
     */
    public boolean hasUntaint() {
        return paramUntaintnessSet != 0;
    }

    public boolean hasTaint() {
        return paramTaintnessSet != 0;
    }

    @Override
    public String toString() {
        StringBuffer buf = new StringBuffer();

        buf.append('{');
        for (int i = 0; i < 32; ++i) {
            if (isUntaint(i)) {
                if (buf.length() > 1) {
                    buf.append(',');
                }
                buf.append(i);
                buf.append("U");
            }

            if (isTaint(i)) {
                if (buf.length() > 1) {
                    buf.append(',');
                }
                buf.append(i);
                buf.append("T");
            }
        }
        buf.append('}');

        return buf.toString();
    }

    /**
     * Intersect this set with the given set.
     * Useful for summarizing the properties of multiple methods.
     *
     * @param target another set
     */
    public void intersectWith(ParameterTaintnessProperty target) {
        paramTaintnessSet &= target.paramTaintnessSet;
        paramUntaintnessSet &= target.paramUntaintnessSet;
    }

    /**
     * Merge this set with the given set
     *
     * @param target another set
     */
    public void mergeWith(ParameterTaintnessProperty target) {
        target.paramTaintnessSet |= paramTaintnessSet;
        target.paramUntaintnessSet |= paramUntaintnessSet;
        if (target.getSinkSourceLine() == null) {
            target.setSinkSourceLine(getSinkSourceLine());
        }

        if (!target.isDirectSink()) {
            target.setDirectSink(isDirectSink());
        }
    }

    /**
     * Make this object the same as the given one.
     *
     * @param other another ParameterTaintnessProperty
     */
    public void copyFrom(ParameterTaintnessProperty other) {
        this.paramTaintnessSet = other.paramTaintnessSet;
        this.paramUntaintnessSet = other.paramUntaintnessSet;
    }

    public boolean isDirectSink() {
        return directSink;
    }

    public void setDirectSink(boolean directSink) {
        this.directSink = directSink;
    }

    public SourceLineAnnotation getSinkSourceLine() {
        return sinkSourceLine;
    }

    public void setSinkSourceLine(SourceLineAnnotation sinkSourceLine) {
        this.sinkSourceLine = sinkSourceLine;
    }

    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ParameterTaintnessProperty property = (ParameterTaintnessProperty) o;

        return paramTaintnessSet == property.paramTaintnessSet && paramUntaintnessSet == property.paramUntaintnessSet;
    }

    public int hashCode() {
        int result;
        result = paramTaintnessSet;
        result = 31 * result + paramUntaintnessSet;
        return result;
    }
}