package su.msu.cs.lvk.secbugs.ta;

import edu.umd.cs.findbugs.ba.ClassContext;
import edu.umd.cs.findbugs.ba.Location;

/**
 * @author Igor Konnov
 */
public interface TaintUsageCollector {
    void foundTaintSensitiveParameter(ClassContext classContext, Location location, TaintValue taintValue);
}
