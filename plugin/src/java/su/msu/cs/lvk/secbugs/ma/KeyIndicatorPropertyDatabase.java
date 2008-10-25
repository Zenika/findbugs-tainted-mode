package su.msu.cs.lvk.secbugs.ma;

import edu.umd.cs.findbugs.ba.interproc.MethodPropertyDatabase;
import edu.umd.cs.findbugs.ba.interproc.PropertyDatabaseFormatException;

/**
 * Methods database to hold parameters which are known to be tainted.
 * <p/>
 * Copied from edu.umd.cs.findbugs.ba.npe.ParameterNullnessPropertyDatabase
 *
 * @author Igor Konnov
 */
public class KeyIndicatorPropertyDatabase extends MethodPropertyDatabase<KeyIndicatorProperty> {
    @Override
    protected KeyIndicatorProperty decodeProperty(String propStr)
            throws PropertyDatabaseFormatException {
        return KeyIndicatorProperty.valueOf(propStr);
    }

    @Override
    protected String encodeProperty(KeyIndicatorProperty property) {
        return property.getIndicatorType().toString();
    }

}