package su.msu.cs.lvk.secbugs.ma;

import edu.umd.cs.findbugs.ba.AnnotationEnumeration;

import java.util.HashMap;
import java.util.Map;

/**
 * Annotations for key indicators as in OWASP Code Review.
 *
 * @author Igor Konnov
 */
public class KeyIndicatorAnnotation extends AnnotationEnumeration<KeyIndicatorAnnotation> {
    public static final KeyIndicatorAnnotation UNKNOWN = new KeyIndicatorAnnotation("Unknown", 0);
    public static final KeyIndicatorAnnotation VALIDATOR = new KeyIndicatorAnnotation("Validator", 1);
    public static final KeyIndicatorAnnotation ACCESS_CONTROL = new KeyIndicatorAnnotation("Access Control", 2);

    private static Map<KeyIndicatorAnnotation, KeyIndicatorProperty> annotationToProperty
            = new HashMap<KeyIndicatorAnnotation, KeyIndicatorProperty>();
    static {
        annotationToProperty.put(UNKNOWN, new KeyIndicatorProperty(KeyIndicatorProperty.IndicatorType.UNKNOWN));
        annotationToProperty.put(VALIDATOR, new KeyIndicatorProperty(KeyIndicatorProperty.IndicatorType.VALIDATOR));
        annotationToProperty.put(ACCESS_CONTROL, new KeyIndicatorProperty(KeyIndicatorProperty.IndicatorType.ACCESS));
    }

    private final static KeyIndicatorAnnotation[] myValues = {
            UNKNOWN, VALIDATOR, ACCESS_CONTROL
    };

    protected KeyIndicatorAnnotation(String s, int i) {
        super(s, i);
    }

    public static KeyIndicatorAnnotation[] values() {
        return myValues.clone();
    }

    public KeyIndicatorProperty toKeyIndicatorProperty() {
        return annotationToProperty.get(this);
    }
}
