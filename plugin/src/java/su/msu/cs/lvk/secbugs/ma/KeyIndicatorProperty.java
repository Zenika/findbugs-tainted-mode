package su.msu.cs.lvk.secbugs.ma;

/**
 * Property describing key indicator. This property does not really differ from KeyIndicatorAnnotation.
 * May be it is better to annotations w/o properties.
 *
 * @author Igor Konnov
 */
public class KeyIndicatorProperty {
    public enum IndicatorType { UNKNOWN, VALIDATOR, ACCESS }
    private IndicatorType indicatorType;

    public KeyIndicatorProperty(IndicatorType indicatorType) {
        this.indicatorType = indicatorType;
    }

    public IndicatorType getIndicatorType() {
        return indicatorType;
    }

    public void setIndicatorType(IndicatorType indicatorType) {
        this.indicatorType = indicatorType;
    }

    public static KeyIndicatorProperty valueOf(String s) {
        return new KeyIndicatorProperty(IndicatorType.valueOf(s));
    }
}
