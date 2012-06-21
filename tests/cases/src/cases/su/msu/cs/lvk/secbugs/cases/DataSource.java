package su.msu.cs.lvk.secbugs.cases;

import su.msu.cs.lvk.secbugs.annotations.TaintedResult;

/**
 * @author Igor Konnov
 */
public class DataSource {
    @TaintedResult()
    public String getTaintedData(String name) {
        return "tainted";
    }

    public String getUntaintedData(String name) {
        return "untainted";
    }
}
