package su.msu.cs.lvk.secbugs.ta;

import edu.umd.cs.findbugs.ba.interproc.MethodPropertyDatabase;
import edu.umd.cs.findbugs.ba.interproc.PropertyDatabaseFormatException;

/**
 * Methods database to hold parameters which are known to be tainted.
 *
 * Copied from edu.umd.cs.findbugs.ba.npe.ParameterNullnessPropertyDatabase
 *
 * @author Igor Konnov
 */
public class IsParameterTaintedPropertyDatabase extends MethodPropertyDatabase<IsParameterTaintedProperty> {
    @Override
    protected IsParameterTaintedProperty decodeProperty(String propStr)
            throws PropertyDatabaseFormatException {
        try {
            int untaintSet = Integer.parseInt(propStr);
            IsParameterTaintedProperty prop = new IsParameterTaintedProperty();
            prop.setUntaintParamSet(untaintSet);
            return prop;
        } catch (NumberFormatException e) {
            throw new PropertyDatabaseFormatException("Invalid untaint param set: " + propStr);
        }
    }

    @Override
    protected String encodeProperty(IsParameterTaintedProperty property) {
        return String.valueOf(property.getUntaintParamSet());
    }

}
