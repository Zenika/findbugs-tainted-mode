package su.msu.cs.lvk.secbugs.junit;

import edu.umd.cs.findbugs.BugCollection;
import edu.umd.cs.findbugs.Project;
import edu.umd.cs.findbugs.SortedBugCollection;
import junit.framework.TestCase;

import java.io.*;

import org.dom4j.DocumentException;

/**
 * @author Igor Konnov
 */
public abstract class AbstractFindbugsTestCase extends TestCase {
    private Project project;
    private BugCollection bugCollection;

    protected void runFindBugs(String targetClassName, String targetMethodName, String bugType) {
        String executable = getFindbugsExecutable();
        String testClasspath = getTestClasspath();
        String auxClasspath = getAuxClasspath();
        String srcClasspath = getSourceClasspath();
        File filterFile = createFilterFile(targetClassName, targetMethodName, bugType);
        File outputFile = getOutputFile();
        String[] args = {
                executable, "-textui",
                "-auxclasspath", auxClasspath,
                "-sourcepath", srcClasspath,
                "-include", filterFile.getAbsolutePath(),
                "-xml", "-output", outputFile.getAbsolutePath(),
                testClasspath
        };
        try {
            System.out.println("Executing: " + join(args, " "));
            ProcessBuilder builder = new ProcessBuilder(args);
            builder.redirectErrorStream(true);
            Process proc = builder.start();

            byte[] buffer = new byte[1024];
            InputStream input = proc.getInputStream();
            int cnt;
            while ((cnt = input.read(buffer)) > 0) {
                System.out.write(buffer, 0, cnt);
            }

            int exitCode = proc.waitFor();
            assertEquals(0, exitCode);
        } catch (IOException e) {
            throw new RuntimeException("Error running executable: " + join(args, " "));
        } catch (InterruptedException e) {
            // just exit
        }

        this.project = new Project();
        bugCollection = readCollection(this.project);
    }

    protected BugCollection readCollection(Project project) {
        BugCollection collection = new SortedBugCollection();
        File outputFile = getOutputFile();
        try {
            collection.readXML(outputFile.getAbsolutePath(), project);
        } catch (IOException e) {
            throw new RuntimeException("Error reading output collection: " + outputFile, e);
        } catch (DocumentException e) {
            throw new RuntimeException("Error reading output collection: " + outputFile, e);
        }

        return collection;
    }

    public Project getProject() {
        return project;
    }

    public BugCollection getBugCollection() {
        return bugCollection;
    }

    public File getOutputFile() {
        return new File(getSystemProperty("build.dir"), "output.xml");
    }

    private File createFilterFile(String targetClassName, String targetMethodName, String bugType) {
        File file = new File(getBuildDir(), "filter.xml");
        PrintWriter writer;
        try {
            writer = new PrintWriter(new OutputStreamWriter(new FileOutputStream(file), "utf-8"));
        } catch (IOException e) {
            throw new RuntimeException("Error opening filter file for writing: " + file, e);
        }
        try {
            writer.println("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
            writer.println("<FindBugsFilter>");
            writer.println("    <Match>");
            writer.println("        <Bug pattern=\"" + bugType + "\"/>");
            writer.println("        <Class name=\"" + targetClassName + "\"/>");
            writer.println("        <Method name=\"" + targetMethodName + "\"/>");
            writer.println("    </Match>");
            writer.println("</FindBugsFilter>");
        } finally {
            writer.close();
        }

        return file;
    }

    public String getBuildDir() {
        return getSystemProperty("build.dir");
    }

    public String getAuxClasspath() {
        return getSystemProperty("aux.classpath");
    }

    public String getTestClasspath() {
        return getSystemProperty("test.classpath");
    }

    public String getSourceClasspath() {
        return getSystemProperty("src.classpath");
    }

    public String getFindbugsHome() {
        return getSystemProperty("findbugs.home");
    }

    public String getFindbugsExecutable() {
        return getSystemProperty("findbugs.executable");
    }

    private String getSystemProperty(String name) {
        String executable = System.getProperty(name, null);
        if (executable == null) {
            throw new RuntimeException("System property " + name + " not found");
        }

        return executable;
    }

    private String join(String[] arr, String delimiter) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < arr.length; ++i) {
            if (i != 0) {
                builder.append(delimiter);
            }
            builder.append(arr[i]);
        }

        return builder.toString();
    }
}
