package su.msu.cs.lvk.secbugs.bta;

import edu.umd.cs.findbugs.ba.Frame;

/**
 * @author Igor Konnov
 */
public class TaintnessFrame extends Frame<TaintnessValue> {
    public TaintnessFrame(int numLocals) {
        super(numLocals);
    }

    /**
     * Convert to string.
     *
     * Create a RLE representation, i.e. one T stands for itself, but several T's are shown as nT. 
     */
    @Override
    public String toString() {
        if (isTop())
            return "[TOP]";
        if (isBottom())
            return "[BOTTOM]";
        StringBuffer buf = new StringBuffer();
        buf.append('[');
        String prevValue = null;
        int accumCnt = 0;
        int numSlots = getNumSlots();
        int start = 0;
        for (int i = start; i < numSlots; ++i) {
            if (i == getNumLocals()) {
                // Use a "|" character to visually separate locals from
                // the operand stack.
                int last = buf.length() - 1;
                if (last >= 0) {
                    if (buf.charAt(last) == ',')
                        buf.deleteCharAt(last);
                }

                if (prevValue != null) {
                    // show trailing values of locals
                    if (accumCnt > 1) {
                        buf.append(accumCnt);
                    }
                    buf.append(prevValue);
                    accumCnt = 0;
                }
                prevValue = null;
                
                buf.append('|');
            }
            String value = valueToString(getValue(i));
            boolean isLast = (i == numSlots - 1);
            if (isLast && value.endsWith(","))
                value = value.substring(0, value.length() - 1);

            if (!isLast && (prevValue == null || prevValue.equals(value))) {
                accumCnt++;
                prevValue = value;
            } else {
                boolean lastAccumulated = false;
                // show packed previous values
                if (prevValue != null) {
                    if (isLast && prevValue.equals(value)) {
                        lastAccumulated = true;
                        ++accumCnt;
                    }
                    if (accumCnt > 1) {
                        buf.append(accumCnt);
                    }
                    buf.append(prevValue);
                }
                accumCnt = 1;
                prevValue = value;

                if (isLast && !lastAccumulated) {
                    buf.append(value);
                }
            }
        }
        buf.append(']');
        return buf.toString();
    }

}
