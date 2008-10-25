package su.msu.cs.lvk.secbugs.cases;

import java.io.*;

/**
 * Test cases of taint analysis.
 *
 * @author Igor Konnov
 */
public class TaintedCase {
    private DataSource source = new DataSource();
    private SensitiveSinks sinks = new SensitiveSinks();

    // parameter is untainted
    public void untainted() {
        String foo = source.getUntaintedData("foo");
        sinks.sensitive(foo);
    }

    // parameter is tainted, but method is insensitive
    public void taintedToInsensitive() {
        String foo = source.getTaintedData("foo");
        sinks.insensitive(foo);
    }

    // parameter is tainted in the basic block
    public void oneBlock() {
        String foo = source.getTaintedData("foo");
        sinks.sensitive(foo);
    }

    // parameter is tainted in one branch
    public void branch() {
        String tainted = source.getTaintedData("foo");
        String untainted = source.getUntaintedData("bar");

        if ("untainted".equals(untainted)) {
            sinks.sensitive(tainted);
        } else {
            sinks.insensitive(tainted);
        }
    }

    // parameter is tainted via assignment
    public void assignment() {
        String foo = source.getTaintedData("foo");
        String bar = foo;
        sinks.sensitive(bar);
    }

    // actual parameter is tainted
    public void callDirectly() {
        sinks.sensitive(source.getTaintedData("foo"));
    }

    // actual parameter is tainted
    public void callDirectlyWithAddition() {
        sinks.sensitive("a" + source.getTaintedData("foo") + "z");
    }

    public void interCaller() {
        String tainted = source.getTaintedData("foo");
        interCallee(tainted);
    }

    // parameter is tainted via call in interCaller
    public void interCallee(String tainted) {
        sinks.sensitive(tainted);
    }

    public void validatorUntaintsOneBranch() {
        SampleValidator validator = new SampleValidator();
        String untainted = source.getTaintedData("foo");
        if (validator.isUntainted(untainted)) {
            sinks.sensitive(untainted);
        } else {
            System.out.println("Do nothing");
        }
    }

    public void validatorLeavesOtherBranchTainted() {
        SampleValidator validator = new SampleValidator();
        String tainted = source.getTaintedData("foo");
        if (validator.isUntainted(tainted)) {
            System.out.println("Untainted data, do anything, you want");
        } else {
            sinks.sensitive(tainted);
        }
    }

    public void validatorUntaintsOneBranchNeg() {
        SampleValidator validator = new SampleValidator();
        String untainted = source.getTaintedData("foo");
        if (!validator.isUntainted(untainted)) {
            System.out.println("Do nothing");
        } else {
            sinks.sensitive(untainted);
        }
    }

    public void validatorLeavesOtherBranchTaintedNeg() {
        SampleValidator validator = new SampleValidator();
        String tainted = source.getTaintedData("foo");
        if (!validator.isUntainted(tainted)) {
            sinks.sensitive(tainted);
        } else {
            System.out.println("Untainted data, do anything, you want");
        }
    }

    public void untaintedMethodThrowsException() throws IOException {
        OutputStream out = new ByteArrayOutputStream();
        throw new IOException("Foo!");
    }

    public void untaintedMethodRethrowsException() throws IOException {
        OutputStream out = new ByteArrayOutputStream();
        out.write("bar!".getBytes());
        out.close();
    }

    public void untaintedMethodRethrowsExceptionWithFinally() throws IOException {
        OutputStream out = null;
        try {
            out = new ByteArrayOutputStream();
            out.write("bar!".getBytes());
            out.close();
        } finally {
            if (out != null) {
                out.close();
            }
        }
    }

    public void untaintedMethodCatchesException() {
        OutputStream out = new ByteArrayOutputStream();
        try {
            out.write("bar!".getBytes());
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void untaintedMethodTryCatchFinallyThrows() throws Throwable {
        Object a = null, b = null, c = null, d = null, f = null, g = null;
        PrintWriter out = new PrintWriter(new OutputStreamWriter(new ByteArrayOutputStream()));
        PrintWriter jspx_out = null;
        try {
            out.println("bar!".getBytes("cp1251"));

            out.close();
            out = null;
        } catch (Throwable t) {
            if (!(t instanceof UnsupportedEncodingException)) {
                jspx_out = out;
                if (jspx_out != null && jspx_out.checkError())
                    jspx_out.flush();
                if (jspx_out != null) jspx_out.println(t);
            }
            throw t;
        } finally {
            out.close();
            String untainted = source.getUntaintedData("foo");
            System.loadLibrary("foo");
        }

    }
}
