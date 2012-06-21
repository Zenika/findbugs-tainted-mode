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
public class IsResultTaintedPropertyDatabase extends MethodPropertyDatabase<IsResultTaintedProperty> {
    @Override
    protected IsResultTaintedProperty decodeProperty(String propStr)
            throws PropertyDatabaseFormatException {
        boolean tainted = Boolean.parseBoolean(propStr);
        return new IsResultTaintedProperty(tainted);
    }

    @Override
    protected String encodeProperty(IsResultTaintedProperty property) {
        return String.valueOf(property.isTainted());
    }

}