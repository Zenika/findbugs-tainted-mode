package su.msu.cs.lvk.secbugs.cases;

import su.msu.cs.lvk.secbugs.annotations.TaintnessValidator;

/**
 * @author Igor Konnov
 */
public class SampleValidator {
    @TaintnessValidator
    public boolean isUntainted(String data) {
        return data.startsWith("untainted");
    }
}
