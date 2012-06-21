package su.msu.cs.lvk.secbugs.ta;

import edu.umd.cs.findbugs.FindBugs;
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

import java.io.*;

/**
 * Database for taintness annotations of methods and parameters.
 *
 * @author Igor Konnov
 */
public class TaintAnnotationDatabase extends AnnotationDatabase<TaintedAnnotation> {
    /**
     * Filename of database, where annotations are stored externally.
     */
    public static final String DATABASE_FILENAME = ".secbugs_annotations";

    private static final boolean DEBUG = SystemProperties.getBoolean("secbugs.ta.debug");

    private TypeQualifierValue taintedResultTypeQualifierValue;
    private TypeQualifierValue sensitiveParamTypeQualifierValue;
    private static final String TAINTED_RESULT_ANNOTATION = "su/msu/cs/lvk/secbugs/annotations/TaintedResult";
    private static final String SENSITIVE_PARAM_ANNOTATION = "su/msu/cs/lvk/secbugs/annotations/Sensitive";
    private static final String FIELD_DELIMITER = "\\|";
    private static final String STATIC_KEY = "static";

    public TaintAnnotationDatabase() {
        ClassDescriptor classDesc = DescriptorFactory.instance().getClassDescriptor(TAINTED_RESULT_ANNOTATION);
        taintedResultTypeQualifierValue = TypeQualifierValue.getValue(classDesc, null);
        ClassDescriptor sensitiveClassDesc = DescriptorFactory.instance().getClassDescriptor(SENSITIVE_PARAM_ANNOTATION);
        sensitiveParamTypeQualifierValue = TypeQualifierValue.getValue(sensitiveClassDesc, null);

        readDatabaseIfPresent();
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
    private void addMethodAnnotation(String cName, String mName, String sig, boolean isStatic, AnnotationValue annotationValue) {
        if (DEBUG) {
            System.out.println("addMethodAnnotation: annotate " + cName + "." + mName + " with " + annotationValue);
        }
        XMethod xmethod = getXMethod(cName, mName, sig, isStatic);
        if (xmethod == null) return;

        // Destructively add the annotationValue to the MethodInfo object
        ((MethodInfo) xmethod).addAnnotation(annotationValue);
    }

    /* (non-Javadoc)
     * @see edu.umd.cs.findbugs.ba.INullnessAnnotationDatabase#addMethodParameterAnnotation(java.lang.String, java.lang.String, java.lang.String, boolean, int, edu.umd.cs.findbugs.ba.NullnessAnnotation)
     */
    public void addMethodParameterAnnotation(String cName, String mName, String sig, boolean isStatic, int param,
                                             AnnotationValue annotationValue) {
        if (DEBUG) {
            System.out.println("addMethodParameterAnnotation: annotate " + cName + "." + mName + " param " + param + " with " + annotationValue);
        }
        XMethod xmethod = getXMethod(cName, mName, sig, isStatic);
        if (xmethod == null) return;

        if (!(xmethod instanceof MethodInfo)) {
            if (false)
                AnalysisContext.logError("Could not fully resolve method " + cName + "." + mName + sig + " to apply annotation " + annotationValue);
            return;
        }
        if (!xmethod.getClassName().equals(cName)) {
            if (false)
                AnalysisContext.logError("Could not fully resolve method " + cName + "." + mName + sig + " to apply annotation " + annotationValue);
            return;
        }

        // Destructively add the annotation to the MethodInfo object
        ((MethodInfo) xmethod).addParameterAnnotation(param, annotationValue);
    }

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

        // TODO: check in another way
        if (tqa.typeQualifier.typeQualifier.getClassName().equals(TAINTED_RESULT_ANNOTATION)) {
            return TaintedAnnotation.ALWAYS_TAINTED;
        } else if (tqa.typeQualifier.typeQualifier.getClassName().equals(SENSITIVE_PARAM_ANNOTATION)) {
            return TaintedAnnotation.NEVER_TAINTED;
        }


        return TaintedAnnotation.ALWAYS_TAINTED;
    }

    private void readDatabaseIfPresent() {
        File file = new File(FindBugs.getHome(), DATABASE_FILENAME);
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader(file));
            String line = reader.readLine();
            while (line != null) {
                parseLine(line);
                line = reader.readLine();
            }
        } catch (FileNotFoundException e) {
            if (DEBUG) {
                System.out.println("TaintedAnnotationDatabase file " + file + " not found");
            }
        } catch (IOException e) {
            System.err.println("Exception while reading TaintedAnnotationDatabase file: " + file);
            e.printStackTrace(System.err);
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    // ignore
                }
            }
        }
    }

    private void parseLine(String line) {
        String[] parts = line.split(FIELD_DELIMITER);

        if ("TaintedResult".equals(parts[0])) {
            if (parts.length != 5) {
                System.err.println("Corrupted line: " + line);
            } else {
                String className = parts[1];
                String methodName = parts[2];
                String sig = parts[3];
                boolean isStatic = STATIC_KEY.equals(parts[4]);
                addMethodAnnotation(className, methodName, sig, isStatic,
                        new AnnotationValue(DescriptorFactory.instance().getClassDescriptor(TAINTED_RESULT_ANNOTATION)));
            }
        } else if ("Sensitive".equals(parts[0])) {
            if (parts.length != 6) {
                System.err.println("Corrupted line: " + line);
            } else {
                String className = parts[1];
                String methodName = parts[2];
                String sig = parts[3];
                boolean isStatic = STATIC_KEY.equals(parts[4]);
                int paramNum = Integer.parseInt(parts[5]);
                addMethodParameterAnnotation(className, methodName, sig, isStatic, paramNum,
                        new AnnotationValue(DescriptorFactory.instance().getClassDescriptor(SENSITIVE_PARAM_ANNOTATION)));
            }

        }
    }
}
