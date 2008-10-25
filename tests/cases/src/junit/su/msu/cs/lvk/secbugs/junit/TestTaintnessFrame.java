package su.msu.cs.lvk.secbugs.junit;

import junit.framework.TestCase;
import su.msu.cs.lvk.secbugs.bta.TaintnessFrame;
import su.msu.cs.lvk.secbugs.bta.TaintnessValue;

/**
 * @author Igor Konnov
 */
public class TestTaintnessFrame extends TestCase {
    public void testToStringEmptyStackOneLocal() {
        TaintnessFrame frame = new TaintnessFrame(1);
        frame.setValue(0, new TaintnessValue());
        String str = frame.toString();
        assertEquals("[T]", str);
    }

    public void testToStringEmptyStackTwoLocals() {
        TaintnessFrame frame = new TaintnessFrame(2);
        frame.setValue(0, new TaintnessValue());
        frame.setValue(1, new TaintnessValue());
        String str = frame.toString();
        assertEquals("[2T]", str);
    }

    public void testToStringEmptyStackThreeLocals() {
        TaintnessFrame frame = new TaintnessFrame(3);
        for (int i = 0; i < 3; ++i) {
            frame.setValue(i, new TaintnessValue());
        }
        String str = frame.toString();
        assertEquals("[3T]", str);
    }

    public void testToStringThreeLocalsOneOperand() {
        TaintnessFrame frame = new TaintnessFrame(3);
        for (int i = 0; i < 3; ++i) {
            frame.setValue(i, new TaintnessValue());
        }
        frame.pushValue(new TaintnessValue());
        String str = frame.toString();
        assertEquals("[3T|T]", str);
    }

    public void testToStringThreeLocalsTwoOperands() {
        TaintnessFrame frame = new TaintnessFrame(3);
        for (int i = 0; i < 3; ++i) {
            frame.setValue(i, new TaintnessValue());
        }
        frame.pushValue(new TaintnessValue());
        frame.pushValue(new TaintnessValue());
        String str = frame.toString();
        assertEquals("[3T|2T]", str);
    }

    public void testToStringLocals2UT() {
        TaintnessFrame frame = new TaintnessFrame(3);
        TaintnessValue untainted = new TaintnessValue();
        untainted.setUntainted(true);
        untainted.setTainted(false);
        TaintnessValue tainted = new TaintnessValue();
        frame.setValue(0, untainted);
        frame.setValue(1, untainted);
        frame.setValue(2, tainted);
        String str = frame.toString();
        assertEquals("[2UT]", str);
    }

    public void testToStringLocalsT2U() {
        TaintnessFrame frame = new TaintnessFrame(3);
        TaintnessValue untainted = new TaintnessValue();
        untainted.setUntainted(true);
        untainted.setTainted(false);
        TaintnessValue tainted = new TaintnessValue();
        frame.setValue(0, tainted);
        frame.setValue(1, untainted);
        frame.setValue(2, untainted);
        String str = frame.toString();
        assertEquals("[T2U]", str);
    }

    public void testToStringLocalsT2UT() {
        TaintnessFrame frame = new TaintnessFrame(4);
        TaintnessValue untainted = new TaintnessValue();
        untainted.setUntainted(true);
        untainted.setTainted(false);
        TaintnessValue tainted = new TaintnessValue();
        frame.setValue(0, tainted);
        frame.setValue(1, untainted);
        frame.setValue(2, untainted);
        frame.setValue(3, tainted);
        String str = frame.toString();
        assertEquals("[T2UT]", str);
    }

    public void testToStringLocalsT2UTStackT2UT() {
        TaintnessFrame frame = new TaintnessFrame(4);
        TaintnessValue untainted = new TaintnessValue();
        untainted.setUntainted(true);
        untainted.setTainted(false);
        TaintnessValue tainted = new TaintnessValue();
        frame.setValue(0, tainted);
        frame.setValue(1, untainted);
        frame.setValue(2, untainted);
        frame.setValue(3, tainted);
        frame.pushValue(tainted);
        frame.pushValue(untainted);
        frame.pushValue(untainted);
        frame.pushValue(tainted);
        String str = frame.toString();
        assertEquals("[T2UT|T2UT]", str);
    }

    public void testToStringLocalsT2U2TStackT2UT() {
        TaintnessFrame frame = new TaintnessFrame(5);
        TaintnessValue untainted = new TaintnessValue();
        untainted.setUntainted(true);
        untainted.setTainted(false);
        TaintnessValue tainted = new TaintnessValue();
        frame.setValue(0, tainted);
        frame.setValue(1, untainted);
        frame.setValue(2, untainted);
        frame.setValue(3, tainted);
        frame.setValue(4, tainted);
        frame.pushValue(tainted);
        frame.pushValue(untainted);
        frame.pushValue(untainted);
        frame.pushValue(tainted);
        String str = frame.toString();
        assertEquals("[T2U2T|T2UT]", str);
    }
}
