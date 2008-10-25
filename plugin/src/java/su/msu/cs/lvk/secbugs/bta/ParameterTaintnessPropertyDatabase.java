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
    private static final String DELIMITER = "#";

    @Override
    protected ParameterTaintnessProperty decodeProperty(String propStr)
            throws PropertyDatabaseFormatException {
        try {
            String[] s = propStr.split(DELIMITER);
            if (s.length != 3) {
                throw new PropertyDatabaseFormatException("Invalid property: " + propStr);
            }
            int taintness = Integer.parseInt(s[0]);
            int untaintness = Integer.parseInt(s[1]);
            boolean directSink = Boolean.parseBoolean(s[2]);
            ParameterTaintnessProperty prop = new ParameterTaintnessProperty();
            prop.setParamTaintnessSet(taintness);
            prop.setParamUntaintnessSet(untaintness);
            prop.setDirectSink(directSink);
            return prop;
        } catch (NumberFormatException e) {
            throw new PropertyDatabaseFormatException("Invalid untaint param set: " + propStr);
        }
    }

    @Override
    protected String encodeProperty(ParameterTaintnessProperty property) {
        return String.valueOf(property.getParamTaintnessSet())
                + DELIMITER + String.valueOf(property.getParamUntaintnessSet())
                + DELIMITER + String.valueOf(property.isDirectSink());
    }

}