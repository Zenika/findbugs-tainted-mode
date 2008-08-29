package su.msu.cs.lvk.secbugs.ta;

import edu.umd.cs.findbugs.SystemProperties;
import edu.umd.cs.findbugs.ba.*;
import edu.umd.cs.findbugs.ba.jsr305.TypeQualifierAnnotation;
import edu.umd.cs.findbugs.ba.jsr305.TypeQualifierApplications;
import edu.umd.cs.findbugs.ba.jsr305.TypeQualifierValue;
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import edu.umd.cs.findbugs.classfile.ClassDescriptor;
import edu.umd.cs.findbugs.classfile.DescriptorFactory;
import edu.umd.cs.findbugs.classfile.Global;
import edu.umd.cs.findbugs.classfile.analysis.AnnotatedObject;
import edu.umd.cs.findbugs.classfile.analysis.AnnotationValue;
import edu.umd.cs.findbugs.classfile.analysis.ClassInfo;
import edu.umd.cs.findbugs.classfile.analysis.MethodInfo;
import edu.umd.cs.findbugs.log.Profiler;

/**
 * @author Igor Konnov
 */
public class TaintAnnotationDatabase extends AnnotationDatabase<TaintedAnnotation> {
    private static final boolean DEBUG = SystemProperties.getBoolean("secbugs.ta.debug");

    private TypeQualifierValue taintedResultTypeQualifierValue;
    private TypeQualifierValue sensitiveParamTypeQualifierValue;
    private static final String TAINTED_RESULT_ANNOTATION = "su/msu/cs/lvk/secbugs/annotations/TaintedResult";
    private static final String SENSITIVE_PARAM_ANNOTATION = "su/msu/cs/lvk/secbugs/annotations/Sensitive";

    public TaintAnnotationDatabase() {
        ClassDescriptor classDesc = DescriptorFactory.instance().getClassDescriptor(TAINTED_RESULT_ANNOTATION);
        taintedResultTypeQualifierValue = TypeQualifierValue.getValue(classDesc, null);
        ClassDescriptor sensitiveClassDesc = DescriptorFactory.instance().getClassDescriptor(SENSITIVE_PARAM_ANNOTATION);
        sensitiveParamTypeQualifierValue = TypeQualifierValue.getValue(sensitiveClassDesc, null);
    }

    /* (non-Javadoc)
     * @see edu.umd.cs.findbugs.ba.INullnessAnnotationDatabase#getResolvedAnnotation(java.lang.Object, boolean)
     */
    public TaintedAnnotation getResolvedAnnotation(Object o, boolean getMinimal) {
        Profiler profiler = Profiler.getInstance();
        profiler.start(this.getClass());
        try {
            if (DEBUG) {
                System.out.println("getResolvedAnnotation: o = " + o + "...");
            }

            TypeQualifierAnnotation tqa = null;

            if (o instanceof XMethodParameter) {
                XMethodParameter param = (XMethodParameter) o;

                tqa = TypeQualifierApplications.getEffectiveTypeQualifierAnnotation(
                        param.getMethod(), param.getParameterNumber(), sensitiveParamTypeQualifierValue);
            } else if (o instanceof XMethod || o instanceof XField) {
                tqa = TypeQualifierApplications.getEffectiveTypeQualifierAnnotation(
                        (AnnotatedObject) o, taintedResultTypeQualifierValue);
            }

            TaintedAnnotation result = toTaintedAnnotation(tqa);
            if (DEBUG) {
                System.out.println("   ==> " + (result != null ? result.toString() : "not found"));
            }
            return result;
        } finally {
            profiler.end(this.getClass());
        }
    }

    /*
    public void addFieldAnnotation(String cName, String mName, String mSig, boolean isStatic, TaintedAnnotation annotation) {
        if (DEBUG) {
            System.out.println("addFieldAnnotation: annotate " + cName + "." + mName + " with " + annotation);
        }

        XField xfield = XFactory.createXField(cName, mName, mSig, isStatic);
        if (!(xfield instanceof FieldInfo)) {
            if (DEBUG) {
                System.out.println("  Field not found! " + cName + "." + mName + ":" + mSig + " " + isStatic + " " + annotation);
            }
            return;
        }

        // Get JSR-305 nullness annotation type
        ClassDescriptor nullnessAnnotationType = getNullnessAnnotationClassDescriptor(annotation);

        // Create an AnnotationValue
        AnnotationValue annotationValue = new AnnotationValue(nullnessAnnotationType);

        // Destructively add the annotation to the FieldInfo object
        ((FieldInfo) xfield).addAnnotation(annotationValue);
    }
    */

    public XMethod getXMethod(String cName, String mName, String sig, boolean isStatic) {
        ClassDescriptor classDesc = DescriptorFactory.instance().getClassDescriptorForDottedClassName(cName);
        ClassInfo xclass;

        // Get the XClass (really a ClassInfo object)
        try {
            xclass = (ClassInfo) Global.getAnalysisCache().getClassAnalysis(XClass.class, classDesc);
        } catch (edu.umd.cs.findbugs.classfile.MissingClassException e) {
            if (DEBUG) {
                System.out.println("  Class not found!");
            }
//			AnalysisContext.currentAnalysisContext().getLookupFailureCallback().reportMissingClass(e.getClassDescriptor());
            return null;
        } catch (CheckedAnalysisException e) {
            if (DEBUG) {
                System.out.println("  Class not found!");
            }
//			AnalysisContext.logError("Error adding built-in nullness annotation", e);
            return null;
        }
        XMethod xmethod = xclass.findMethod(mName, sig, isStatic);

        if (xmethod == null)
            xmethod = XFactory.createXMethod(cName, mName, sig, isStatic);
        if (xmethod == null || !xmethod.isResolved()) {
            if (DEBUG) {
                for (XMethod mm : xclass.getXMethods())
                    if (mm.getName().equals(mName)) System.out.println(mm);
                System.out.println("  Method not found!");
            }
            return null;
        }
        return xmethod;

    }

    /* (non-Javadoc)
    * @see edu.umd.cs.findbugs.ba.INullnessAnnotationDatabase#addMethodAnnotation(java.lang.String, java.lang.String, java.lang.String, boolean, edu.umd.cs.findbugs.ba.NullnessAnnotation)
    */
    public void addMethodAnnotation(String cName, String mName, String sig, boolean isStatic, TaintedAnnotation annotation) {
        if (DEBUG) {
            System.out.println("addMethodAnnotation: annotate " + cName + "." + mName + " with " + annotation);
        }
        XMethod xmethod = getXMethod(cName, mName, sig, isStatic);
        if (xmethod == null) return;
        // Get tainted annotation type
        ClassDescriptor taintedAnnotationType = DescriptorFactory.instance().getClassDescriptor(TAINTED_RESULT_ANNOTATION);
// TODO: add like that ->  ClassDescriptor nullnessAnnotationType = getTaintedAnnotationClassDescriptor(annotation);

        // Create an AnnotationValue
        AnnotationValue annotationValue = new AnnotationValue(taintedAnnotationType);

        // Destructively add the annotation to the MethodInfo object
        ((MethodInfo) xmethod).addAnnotation(annotationValue);
    }

    /* (non-Javadoc)
     * @see edu.umd.cs.findbugs.ba.INullnessAnnotationDatabase#addMethodParameterAnnotation(java.lang.String, java.lang.String, java.lang.String, boolean, int, edu.umd.cs.findbugs.ba.NullnessAnnotation)
     */
    /*
    public void addMethodParameterAnnotation(@DottedClassName String cName, String mName, String sig, boolean isStatic, int param,
                                             NullnessAnnotation annotation) {
        if (DEBUG) {
            System.out.println("addMethodParameterAnnotation: annotate " + cName + "." + mName + " param " + param + " with " + annotation);
        }
        XMethod xmethod = getXMethod(cName, mName, sig, isStatic);
        if (xmethod == null) return;

        if (!(xmethod instanceof MethodInfo)) {
            if (false)
                AnalysisContext.logError("Could not fully resolve method " + cName + "." + mName + sig + " to apply annotation " + annotation);
            return;
        }
        if (!xmethod.getClassName().equals(cName)) {
            if (false)
                AnalysisContext.logError("Could not fully resolve method " + cName + "." + mName + sig + " to apply annotation " + annotation);
            return;
        }

        // Get JSR-305 nullness annotation type
        ClassDescriptor nullnessAnnotationType = getNullnessAnnotationClassDescriptor(annotation);

        // Create an AnnotationValue
        AnnotationValue annotationValue = new AnnotationValue(nullnessAnnotationType);

        // Destructively add the annotation to the MethodInfo object
        ((MethodInfo) xmethod).addParameterAnnotation(param, annotationValue);
    }
    */

    /**
     * Convert a TaintedResult-based TypeQualifierAnnotation
     * into a TaintedAnnotation.
     *
     * @param tqa TaintValue-based TypeQualifierAnnotation
     * @return corresponding NullnessAnnotation
     */
    private TaintedAnnotation toTaintedAnnotation(TypeQualifierAnnotation tqa) {
        if (tqa == null) {
            return null;
        }

        // XXX: check in another way
        if (tqa.typeQualifier.typeQualifier.getClassName().equals(TAINTED_RESULT_ANNOTATION)) {
            return TaintedAnnotation.ALWAYS_TAINTED;
        } else if (tqa.typeQualifier.typeQualifier.getClassName().equals(SENSITIVE_PARAM_ANNOTATION)) {
            return TaintedAnnotation.NEVER_TAINTED;
        }


        return TaintedAnnotation.ALWAYS_TAINTED;
    }
}
