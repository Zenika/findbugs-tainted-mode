package su.msu.cs.lvk.secbugs.cases;

import su.msu.cs.lvk.secbugs.annotations.Sensitive;

/**
 * @author Igor Konnov
 */
public class SensitiveSinks {
    public void sensitive(@Sensitive String value) {
        System.out.println("sensitive got value: " + value);
    }

    public void insensitive(String value) {
        System.out.println("insensitive got value: " + value);
    }
}
