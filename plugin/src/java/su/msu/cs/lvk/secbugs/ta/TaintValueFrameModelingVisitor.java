package su.msu.cs.lvk.secbugs.ta;

import edu.umd.cs.findbugs.ba.AbstractFrameModelingVisitor;
import edu.umd.cs.findbugs.ba.XFactory;
import edu.umd.cs.findbugs.ba.XMethod;
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import edu.umd.cs.findbugs.classfile.Global;
import org.apache.bcel.generic.*;

/**
 * @author Igor Konnov
 */
public class TaintValueFrameModelingVisitor extends AbstractFrameModelingVisitor<TaintValue, TaintValueFrame> {
    public TaintValueFrameModelingVisitor(ConstantPoolGen cpg) {
        super(cpg);
    }

    public TaintValue getDefaultValue() {
        return new TaintValue(TaintValue.UNTAINTED);
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

        boolean modelCallReturnValue = (returnType instanceof ReferenceType);

        if (!modelCallReturnValue) {
            // Normal case: Assume returned values are non-reporting non-null.
            handleNormalInstruction(obj);
        } else {
            XMethod calledMethod = XFactory.createXMethod(obj, getCPG());
            if (TaintAnalysis.DEBUG) {
                System.out.println("Check " + calledMethod + " for tainted data return...");
            }

            IsResultTaintedProperty property;
            TaintValue pushValue;
            try {
                IsResultTaintedPropertyDatabase database = Global.getAnalysisCache().getDatabase(IsResultTaintedPropertyDatabase.class);
                property = database.getProperty(calledMethod.getMethodDescriptor());
            } catch (CheckedAnalysisException e) {
                throw new RuntimeException("Error getting TaintAnnotationDatabase");
            }

            if (property != null && property.isTainted()) {
                if (TaintAnalysis.DEBUG) {
                    System.out.println("Method " + calledMethod + " returns tainted data");
                }
                pushValue = new TaintValue(TaintValue.TAINTED, 0);
            } else {
                pushValue = new TaintValue(TaintValue.UNTAINTED);
            }

            modelInstruction(obj, getNumWordsConsumed(obj), getNumWordsProduced(obj), pushValue);
            newValueOnTOS();
        }
    }

    private void newValueOnTOS() {
        // do nothing?
    }
}
