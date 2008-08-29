package su.msu.cs.lvk.secbugs.bta;

import edu.umd.cs.findbugs.ba.interproc.MethodPropertyDatabase;
import edu.umd.cs.findbugs.ba.interproc.PropertyDatabaseFormatException;

/**
 * Methods database to hold parameters which are known to be tainted.
 * <p/>
 * Copied from edu.umd.cs.findbugs.ba.npe.ParameterNullnessPropertyDatabase
 *
 * @author Igor Konnov
 */
public class ParameterTaintnessPropertyDatabase extends MethodPropertyDatabase<ParameterTaintnessProperty> {
    private static final String SET_DELIMITER = "#";

    @Override
    protected ParameterTaintnessProperty decodeProperty(String propStr)
            throws PropertyDatabaseFormatException {
        try {
            String[] s = propStr.split(SET_DELIMITER);
            if (s.length != 2) {
                throw new PropertyDatabaseFormatException("Invalid untaint param set: " + propStr);
            }
            int taintness = Integer.parseInt(s[0]);
            int untaintness = Integer.parseInt(s[1]);
            ParameterTaintnessProperty prop = new ParameterTaintnessProperty();
            prop.setParamTaintnessSet(taintness);
            prop.setParamUntaintnessSet(untaintness);
            return prop;
        } catch (NumberFormatException e) {
            throw new PropertyDatabaseFormatException("Invalid untaint param set: " + propStr);
        }
    }

    @Override
    protected String encodeProperty(ParameterTaintnessProperty property) {
        return String.valueOf(property.getParamTaintnessSet())
                + SET_DELIMITER + String.valueOf(property.getParamUntaintnessSet());
    }

}