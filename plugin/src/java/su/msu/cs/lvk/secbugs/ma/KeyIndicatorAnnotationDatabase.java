package su.msu.cs.lvk.secbugs.ma;

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
 * Database of key indicators.
 *
 * @author Igor Konnov
 */
public class KeyIndicatorAnnotationDatabase extends AnnotationDatabase<KeyIndicatorAnnotation> {
    /**
     * Filename of database, where annotations are stored externally.
     */
    public static final String DATABASE_FILENAME = ".secbugs_annotations";

    private static final boolean DEBUG = SystemProperties.getBoolean("secbugs.ta.debug");

    private TypeQualifierValue taintnessValidatorTypeQualifierValue;
    private static final String TAINTNESS_VALIDATOR_ANNOTATION = "su/msu/cs/lvk/secbugs/annotations/TaintnessValidator";
    private static final String FIELD_DELIMITER = "\\|";
    private static final String STATIC_KEY = "static";

    public KeyIndicatorAnnotationDatabase() {
        ClassDescriptor classDesc = DescriptorFactory.instance().getClassDescriptor(TAINTNESS_VALIDATOR_ANNOTATION);
        taintnessValidatorTypeQualifierValue = TypeQualifierValue.getValue(classDesc, null);

        if (DEBUG) {
            System.out.println("KeyIndicatorAnnotationDatabase created");
        }

        readDatabaseIfPresent();
    }

    public KeyIndicatorAnnotation getResolvedAnnotation(Object o, boolean getMinimal) {
        Profiler profiler = Global.getAnalysisCache().getProfiler();
        profiler.start(this.getClass());
        try {
            if (DEBUG) {
                System.out.println("getResolvedAnnotation: o = " + o + "...");
            }

            TypeQualifierAnnotation tqa = null;

            if (o instanceof XMethod || o instanceof XField) {
                tqa = TypeQualifierApplications.getEffectiveTypeQualifierAnnotation(
                        (AnnotatedObject) o, taintnessValidatorTypeQualifierValue);
            }

            KeyIndicatorAnnotation result = toKeyIndicatorAnnotation(tqa);
            if (DEBUG) {
                System.out.println("   ==> " + (result != null ? result.toString() : "not found"));
            }
            return result;
        } finally {
            profiler.end(this.getClass());
        }
    }

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
            return null;
        } catch (CheckedAnalysisException e) {
            if (DEBUG) {
                System.out.println("  Class not found!");
            }
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

    private void addMethodAnnotation(String cName, String mName, String sig, boolean isStatic, AnnotationValue annotationValue) {
        if (DEBUG) {
            System.out.println("addMethodAnnotation: annotate " + cName + "." + mName + " with " + annotationValue);
        }
        XMethod xmethod = getXMethod(cName, mName, sig, isStatic);
        if (xmethod == null) return;

        // Destructively add the annotationValue to the MethodInfo object
        ((MethodInfo) xmethod).addAnnotation(annotationValue);
    }

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
    private KeyIndicatorAnnotation toKeyIndicatorAnnotation(TypeQualifierAnnotation tqa) {
        if (tqa == null) {
            return null;
        }

        if (tqa.typeQualifier.typeQualifier.getClassName().equals(TAINTNESS_VALIDATOR_ANNOTATION)) {
            return KeyIndicatorAnnotation.VALIDATOR;
        }

        return KeyIndicatorAnnotation.UNKNOWN;
    }

    private void readDatabaseIfPresent() {
        File file = new File(FindBugs.getHome(), DATABASE_FILENAME);
        if (DEBUG) {
            System.out.println("KeyIndicatorAnnotationDatabase: trying to read annotations from " + file);
        }
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
                System.out.println("KeyIndicatorAnnotationDatabase file " + file + " not found");
            }
        } catch (IOException e) {
            System.err.println("Exception while reading KeyIndicatorAnnotationDatabase file: " + file);
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

        if ("TaintnessValidator".equals(parts[0])) {
            if (parts.length != 5) {
                System.err.println("Corrupted line: " + line);
            } else {
                String className = parts[1];
                String methodName = parts[2];
                String sig = parts[3];
                boolean isStatic = STATIC_KEY.equals(parts[4]);
                addMethodAnnotation(className, methodName, sig, isStatic,
                        new AnnotationValue(DescriptorFactory.instance().getClassDescriptor(TAINTNESS_VALIDATOR_ANNOTATION)));
            }
        }
    }
}
