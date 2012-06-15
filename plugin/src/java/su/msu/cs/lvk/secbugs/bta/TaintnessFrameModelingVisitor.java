package su.msu.cs.lvk.secbugs.bta;

import edu.umd.cs.findbugs.SourceLineAnnotation;
import edu.umd.cs.findbugs.ba.*;
import edu.umd.cs.findbugs.ba.type.TypeDataflow;
import edu.umd.cs.findbugs.ba.type.TypeFrame;
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import edu.umd.cs.findbugs.classfile.Global;
import org.apache.bcel.generic.*;

import su.msu.cs.lvk.secbugs.ma.KeyIndicatorProperty;
import su.msu.cs.lvk.secbugs.ma.KeyIndicatorPropertyDatabase;
import su.msu.cs.lvk.secbugs.util.HierarchyUtil;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * @author Igor Konnov
 */
public class TaintnessFrameModelingVisitor extends AbstractBackwardFrameModelingVisitor<TaintnessValue, TaintnessFrame> {
    private JavaClassAndMethod javaClassAndMethod;
    private ParameterTaintnessPropertyDatabase parameterTaintnessPropertyDatabase;
    private KeyIndicatorPropertyDatabase keyIndicatorPropertyDatabase;

    public TaintnessFrameModelingVisitor(JavaClassAndMethod javaClassAndMethod, ConstantPoolGen cpg) throws CheckedAnalysisException {
        super(cpg);
        this.javaClassAndMethod = javaClassAndMethod;
        parameterTaintnessPropertyDatabase = Global.getAnalysisCache().getDatabase(ParameterTaintnessPropertyDatabase.class);
        keyIndicatorPropertyDatabase = Global.getAnalysisCache().getDatabase(KeyIndicatorPropertyDatabase.class);
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
    
    public void visitINVOKESPECIAL(INVOKESPECIAL obj){
    	handleInvoke(obj);
    }

    /**
     * Handle method invocations. Some methods are marked as sources of tainted data, values returned from them
     * should are tainted for sure.
     *
     * @param obj invoke instruction
     */
    private void handleInvoke(InvokeInstruction obj) {
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

        TypeDataflow typeDataflow;
        TypeFrame typeFact;
        try {
            XMethod caller = XFactory.createXMethod(javaClassAndMethod);
            typeDataflow = Global.getAnalysisCache()
                    .getMethodAnalysis(TypeDataflow.class, caller.getMethodDescriptor());
            typeFact = typeDataflow.getFactAtLocation(getLocation());
        } catch (CheckedAnalysisException e) {
            throw new InvalidBytecodeException("Can't obtain type dataflow for " + calledMethod, e);
        }

        try {
            Collection<XMethod> calledMethods = HierarchyUtil.getResolvedMethods(typeFact, obj, cpg);
            for (XMethod targetMethod : calledMethods) {
                checkSensitiveParameters(targetMethod, pushValues, shift);
                checkValidatorParameters(targetMethod, pushValues, shift);
            }
        } catch (ClassNotFoundException e) {
            throw new InvalidBytecodeException("Class not found while analyzing " + calledMethod, e);
        } catch (DataflowAnalysisException e) {
            throw new InvalidBytecodeException("DataflowAnalysisException while analyzing " + calledMethod, e);
        }

        modelInstruction(obj, getNumWordsConsumed(obj), getNumWordsProduced(obj), pushValues);
        newValueOnTOS();
    }

    private void checkSensitiveParameters(XMethod calledMethod, List<TaintnessValue> values, int shift) {
        ParameterTaintnessProperty prop = parameterTaintnessPropertyDatabase.getProperty(calledMethod.getMethodDescriptor());
        if (prop != null) {
            for (int i = 0; i < calledMethod.getNumParams(); ++i) {
                TaintnessValue v = values.get(shift + i);
                v.setTainted(prop.isTaint(i) & v.getTainted());
                v.setUntainted(prop.isUntaint(i) | v.getUntainted());

                if (prop.isDirectSink()) {
                    SourceLineAnnotation source =
                            SourceLineAnnotation.fromVisitedInstruction(javaClassAndMethod.toMethodDescriptor(), getLocation());
                    v.setSinkSourceLine(source);
                }

                if (DEBUG) {
                    System.out.println("Method's " + calledMethod + " parameter " + i + " is untaint?: " + prop.isUntaint(i));
                }
            }
        } else {
            throw new IllegalArgumentException("Called method " + calledMethod
                    + " should be put to taintness database by MethodAnnotationDetector");
        }
    }

    private void checkValidatorParameters(XMethod calledMethod, List<TaintnessValue> values, int shift) {
        KeyIndicatorProperty prop = keyIndicatorPropertyDatabase.getProperty(calledMethod.getMethodDescriptor());
        if (prop != null && prop.getIndicatorType() == KeyIndicatorProperty.IndicatorType.VALIDATOR) {
            for (int i = 0; i < calledMethod.getNumParams(); ++i) {
                TaintnessValue v = values.get(shift + i);
                // all validator parameters may be tainted
               v.setTainted(true);
                v.setUntainted(false);
            } 
        }
    }

    private void newValueOnTOS() {
        // do nothing?
    }
}