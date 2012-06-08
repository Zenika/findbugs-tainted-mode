package su.msu.cs.lvk.secbugs.ta;

import edu.umd.cs.findbugs.SourceLineAnnotation;
import edu.umd.cs.findbugs.SystemProperties;
import edu.umd.cs.findbugs.ba.*;
import edu.umd.cs.findbugs.ba.type.TypeDataflow;
import edu.umd.cs.findbugs.ba.type.TypeFrame;
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import edu.umd.cs.findbugs.classfile.Global;
import org.apache.bcel.Constants;
import org.apache.bcel.generic.*;

import su.msu.cs.lvk.secbugs.util.HierarchyUtil;

import java.util.Collection;

/**
 * @author Igor Konnov
 */
public class TaintValueFrameModelingVisitor extends AbstractFrameModelingVisitor<TaintValue, TaintValueFrame> {
    public static final boolean DEBUG = SystemProperties.getBoolean("ti.analysis.debug");
    private JavaClassAndMethod javaClassAndMethod;

    public TaintValueFrameModelingVisitor(JavaClassAndMethod javaClassAndMethod, ConstantPoolGen cpg)
            throws CheckedAnalysisException {
        super(cpg);
        this.javaClassAndMethod = javaClassAndMethod;
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
    
    public void visitAALOAD(AALOAD obj) {
    	/*
    	 * check if the reference array is tainted
    	 */
    	// To determine the taint value pushed on the stack,
        // we look at the array reference which was
        // popped off of the stack.
        TaintValueFrame frame = getFrame();
        try {
            frame.popValue(); // index
            TaintValue array = frame.popValue(); // arrayref
            TaintValue pushValue = new TaintValue(TaintValue.UNTAINTED);
            if (array.getKind() == TaintValue.TAINTED) {
            	pushValue.meetWith(array);
            }
            frame.pushValue(pushValue);
            
        } catch (DataflowAnalysisException e) {
            throw new InvalidBytecodeException("Stack underflow: " + e.getMessage());
        }
        
    	
    }
    
    public void visitPUTFIELD(PUTFIELD obj){
    	XField field = XFactory.createXField(obj, cpg);
    	TaintAnnotationDatabase tadb = Global.getAnalysisCache().getDatabase(TaintAnnotationDatabase.class);
    	TaintValueFrame frame = getFrame();
    	
    	try {
			TaintValue top = frame.getTopValue();
			if (top.getKind() == TaintValue.TAINTED){
				//add tainted annotation to the field that holds a tainted value
				tadb.addFieldAnnotation(field.getClassName(), field.getName(), field.getSignature(), field.isStatic(), TaintedAnnotation.ALWAYS_TAINTED);
			}
	        super.visitPUTFIELD(obj);
		} catch (DataflowAnalysisException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	
    }
    
    public void visitGETFIELD(GETFIELD obj){
    	//create the field and ask database for its tainted annotation
    	if (getNumWordsProduced(obj) != 1) {
            super.visitGETFIELD(obj);
            return;
        }
		XField field = XFactory.createXField(obj, cpg);
		TaintedAnnotation ta = Global.getAnalysisCache()
				.getDatabase(TaintAnnotationDatabase.class)
				.getResolvedAnnotation(field, false);
		TaintValue pushValue = new TaintValue(TaintValue.UNTAINTED);
		if(ta == TaintedAnnotation.ALWAYS_TAINTED){
			pushValue = new TaintValue(TaintValue.TAINTED, 0);
		}
        modelInstruction(obj, getNumWordsConsumed(obj), getNumWordsProduced(obj), pushValue);

    }

    
    public void handleLoadInstruction(LoadInstruction obj) {
        super.handleLoadInstruction(obj);

        int numProduced = obj.produceStack(cpg);
        if (numProduced == Constants.UNPREDICTABLE) {
            throw new InvalidBytecodeException("Unpredictable stack production");
        }

        int index = obj.getIndex();

        // put source indices of locals
        for (int i = 0; i < numProduced; ++i, ++index) {
            getFrame().setStackValueSourceIndex(i, index);
        }
    }

    /**
     * Handle method invocations. Some methods are marked as sources of tainted data, values returned from them
     * should are tainted for sure.
     *
     * @param obj reference to invoke instruction
     */
    private void handleInvoke(InvokeInstruction obj) {
        Type returnType = obj.getReturnType(getCPG());

        boolean callReturnsReference = (returnType instanceof ReferenceType);

        XMethod calledMethod = XFactory.createXMethod(obj, getCPG());
        propagateTaintedParameterToThis(calledMethod);

        if (!callReturnsReference) {
            handleNormalInstruction(obj);
        } else {
            modelCallReturnValue(obj, calledMethod);
        }
    }

    private void modelCallReturnValue(InvokeInstruction obj, XMethod calledMethod) {
        if (TaintAnalysis.DEBUG) {
            System.out.println("Check " + calledMethod + " for tainted data return...");
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

        Collection<XMethod> calledMethods;
        try {
            calledMethods = HierarchyUtil.getResolvedMethods(typeFact, obj, cpg);
        } catch (ClassNotFoundException e) {
            throw new InvalidBytecodeException("Class not found while analyzing " + calledMethod, e);
        } catch (DataflowAnalysisException e) {
            throw new InvalidBytecodeException("DataflowAnalysisException while analyzing " + calledMethod, e);
        }


        TaintValue pushValue = new TaintValue(TaintValue.UNTAINTED);

        IsResultTaintedProperty property;
        IsResultTaintedPropertyDatabase database = Global.getAnalysisCache().getDatabase(IsResultTaintedPropertyDatabase.class);
        for (XMethod targetMethod : calledMethods) {
   	    property = database.getProperty(targetMethod.getMethodDescriptor());

	    if (property != null) {
	       if (property.isTainted()) {
		   	   if (TaintAnalysis.DEBUG) {
			       System.out.println("Method " + calledMethod + " returns tainted data");
			   }
			   pushValue = new TaintValue(TaintValue.TAINTED, 0);
			   SourceLineAnnotation source = SourceLineAnnotation
				.fromVisitedInstruction(javaClassAndMethod.toMethodDescriptor(), getLocation());
			   pushValue.setSourceLineAnnotation(source);
	       }
	    } else {
	       throw new RuntimeException("Property must be set by MethodAnnotationDetector");
	    }
        }

        meetWithThis(calledMethod, pushValue);

        modelInstruction(obj, getNumWordsConsumed(obj), getNumWordsProduced(obj), pushValue);
        newValueOnTOS();
    }

    /**
     * If object referenced by <i>this</i> is tainted of depth <i>n</i>, then
     * any of its member methods may return tainted value of depth <i>n - 1</i>.
     *
     * @param calledMethod member method to process
     * @param resultValue  value to meet with
     */
    private void meetWithThis(XMethod calledMethod, TaintValue resultValue) {
        if (!calledMethod.isStatic()) {
            try {
                TaintValue thisValue = new TaintValue(getFrame().getStackValue(calledMethod.getNumParams()));
                thisValue.decreaseDepth();
                resultValue.meetWith(thisValue);
            } catch (DataflowAnalysisException e) {
                throw new InvalidBytecodeException("Invalid operands on stack", e);
            }
        }
    }

    /**
     * If tainted parameters are passed to a method, then object referenced by <i>this</i>
     * should be marked as a tainted one, but with a larger depth.
     *
     * @param calledMethod reference to called method
     */
    private void propagateTaintedParameterToThis(XMethod calledMethod) {
    	if (!calledMethod.isStatic()) {
            try {
                TaintValueFrame frame = getFrame();
                TaintValue result = new TaintValue(TaintValue.UNTAINTED);
                int numParams = calledMethod.getNumParams();
                for (int i = 0; i < numParams; ++i) {
                    TaintValue paramValue = frame.getStackValue(i); // order of parameters is irrelevant
                    result.meetWith(paramValue);
                }

                if (result.getKind() == TaintValue.TAINTED) {
                    result.increaseDepth();
                    frame.getStackValue(numParams).meetWith(result);
                }
            } catch (DataflowAnalysisException e) {
                throw new InvalidBytecodeException("Invalid operands on stack", e);
            }
        }
    }

    private void newValueOnTOS() {
        // do nothing?
    }
}
