package su.msu.cs.lvk.secbugs.debug;

import edu.umd.cs.findbugs.ba.Dataflow;
import edu.umd.cs.findbugs.ba.DataflowCFGPrinter;

import java.io.*;

/**
 * Utility class to make debugging easier.
 *
 * @author Igor Konnov
 */
public class DebugUtil {
    public static String printDataflow(Dataflow dataflow, String methodName) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream stream = new PrintStream(baos);
        new DataflowCFGPrinter(dataflow).print(stream);
        try {
            File tempfile = File.createTempFile("dataflow_cfg_" + methodName, ".txt");
            Writer writer = new OutputStreamWriter(new FileOutputStream(tempfile));
            writer.write(baos.toString());
            writer.close();

            return tempfile.getAbsolutePath();
        } catch (IOException e) {
            e.printStackTrace();
            return "error";
        }
    }
}
