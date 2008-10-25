package su.msu.cs.lvk.secbugs.util;

import edu.umd.cs.findbugs.ba.*;
import edu.umd.cs.findbugs.ba.type.TypeFrame;
import org.apache.bcel.generic.ConstantPoolGen;
import org.apache.bcel.generic.InvokeInstruction;

import java.util.HashSet;
import java.util.Set;

/**
 * @author Igor Konnov
 */
public class HierarchyUtil {
    public static Set<XMethod> getResolvedMethods(TypeFrame typeFrame, InvokeInstruction invokeInstruction, ConstantPoolGen cpg) throws ClassNotFoundException, DataflowAnalysisException {
        Set<JavaClassAndMethod> targetMethodSet = Hierarchy
                .resolveMethodCallTargets(invokeInstruction, typeFrame, cpg);
        Set<XMethod> calledMethods = new HashSet<XMethod>();
        for (JavaClassAndMethod m : targetMethodSet) {
            calledMethods.add(XFactory.createXMethod(m));
        }
        calledMethods.add(XFactory.createXMethod(invokeInstruction, cpg));
        return calledMethods;
    }
}
