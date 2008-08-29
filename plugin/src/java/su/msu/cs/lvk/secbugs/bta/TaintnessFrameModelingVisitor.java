package su.msu.cs.lvk.secbugs.bta;

import edu.umd.cs.findbugs.ba.XFactory;
import edu.umd.cs.findbugs.ba.XMethod;
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import edu.umd.cs.findbugs.classfile.Global;
import org.apache.bcel.generic.*;

import java.util.ArrayList;
import java.util.List;

/**
 * @author Igor Konnov
 */
public class TaintnessFrameModelingVisitor extends AbstractBackwardFrameModelingVisitor<TaintnessValue, TaintnessFrame> {
    private ParameterTaintnessPropertyDatabase parameterTaintnessPropertyDatabase;

    public TaintnessFrameModelingVisitor(ConstantPoolGen cpg) throws CheckedAnalysisException {
        super(cpg);
        parameterTaintnessPropertyDatabase = Global.getAnalysisCache().getDatabase(ParameterTaintnessPropertyDatabase.class);
    }

    public TaintnessValue getDefaultValue() {
        return new TaintnessValue();
    }

    public void visitINVOKEVIRTUAL(INVOKEVIRTUAL obj) {
        handleInvoke(obj);
    }

    public void visitINVOKESTATIC(INVOKESTATIC obj) {
        handleInvoke(obj);
    }

    public void visitINVOKEINTERFACE(INVOKEINTERFACE obj) {
        handleInvoke(obj);
    }

    /**
     * Handle method invocations. Some methods are marked as sources of tainted data, values returned from them
     * should are tainted for sure.
     *
     * @param obj
     */
    private void handleInvoke(InvokeInstruction obj) {
        Type callType = obj.getLoadClassType(getCPG());
        Type returnType = obj.getReturnType(getCPG());

        boolean modelParameters = true; // (returnType instanceof ReferenceType);

        if (!modelParameters) {
            handleNormalInstruction(obj);
        } else {
            XMethod calledMethod = XFactory.createXMethod(obj, getCPG());
            if (TaintnessAnalysis.DEBUG) {
                System.out.println("Check " + calledMethod + " for taintness of parameters...");
            }

            int shift = calledMethod.isStatic() ? 0 : 1;
            List<TaintnessValue> pushValues = new ArrayList<TaintnessValue>();

            for (int i = 0; i < calledMethod.getNumParams() + shift; ++i) {
                TaintnessValue value = new TaintnessValue();
                value.setTainted(true);
                value.setUntainted(false);
                pushValues.add(value);
            }

            checkSensitiveParameters(calledMethod, pushValues, shift);

            modelInstruction(obj, getNumWordsConsumed(obj), getNumWordsProduced(obj), pushValues);
            newValueOnTOS();
        }
    }

    // TODO: deal with inheritance!!!
    private void checkSensitiveParameters(XMethod calledMethod, List<TaintnessValue> values, int shift) {
        ParameterTaintnessProperty prop = parameterTaintnessPropertyDatabase.getProperty(calledMethod.getMethodDescriptor());
        if (prop != null) {
            for (int i = 0; i < calledMethod.getNumParams(); ++i) {
                TaintnessValue v = values.get(shift + i);
                v.setTainted(prop.isTaint(i));
                v.setUntainted(prop.isUntaint(i));
            }
        }
    }

    private void newValueOnTOS() {
        // do nothing?
    }
}