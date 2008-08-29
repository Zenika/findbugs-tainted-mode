package su.msu.cs.lvk.secbugs;

import edu.umd.cs.findbugs.classfile.IAnalysisCache;
import edu.umd.cs.findbugs.classfile.IAnalysisEngineRegistrar;
import edu.umd.cs.findbugs.classfile.IMethodAnalysisEngine;
import edu.umd.cs.findbugs.classfile.ReflectionDatabaseFactory;
import su.msu.cs.lvk.secbugs.bta.ParameterTaintnessPropertyDatabase;
import su.msu.cs.lvk.secbugs.bta.TaintnessDataflowFactory;
import su.msu.cs.lvk.secbugs.ta.IsParameterTaintedPropertyDatabase;
import su.msu.cs.lvk.secbugs.ta.IsResultTaintedPropertyDatabase;
import su.msu.cs.lvk.secbugs.ta.TaintAnnotationDatabase;
import su.msu.cs.lvk.secbugs.ta.TaintValueDataflowFactory;

/**
 * @author Igor Konnov
 */
public class EngineRegistrar implements IAnalysisEngineRegistrar {
    private static IMethodAnalysisEngine<?>[] methodAnalysisEngineList = {
            new TaintValueDataflowFactory(),
            new TaintnessDataflowFactory()
    };

    private static Class<?>[] databaseClassList = {
            TaintAnnotationDatabase.class,
            IsParameterTaintedPropertyDatabase.class,
            IsResultTaintedPropertyDatabase.class,
            ParameterTaintnessPropertyDatabase.class
    };

    public void registerAnalysisEngines(IAnalysisCache analysisCache) {
        for (Class cls : databaseClassList) {
            // TODO: how to write it properly using generics???
            analysisCache.registerDatabaseFactory(cls, new ReflectionDatabaseFactory(cls));
        }

        for (IMethodAnalysisEngine<?> engine : methodAnalysisEngineList) {
            engine.registerWith(analysisCache);
        }
    }
}
