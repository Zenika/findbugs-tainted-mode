package su.msu.cs.lvk.secbugs;

import edu.umd.cs.findbugs.classfile.*;
import su.msu.cs.lvk.secbugs.bta.ParameterTaintnessPropertyDatabase;
import su.msu.cs.lvk.secbugs.bta.TaintnessDataflowFactory;
import su.msu.cs.lvk.secbugs.bta.StackDepthDataflowFactory;
import su.msu.cs.lvk.secbugs.ma.KeyIndicatorAnnotationDatabase;
import su.msu.cs.lvk.secbugs.ma.KeyIndicatorPropertyDatabase;
import su.msu.cs.lvk.secbugs.ta.IsResultTaintedPropertyDatabase;
import su.msu.cs.lvk.secbugs.ta.TaintAnnotationDatabase;
import su.msu.cs.lvk.secbugs.ta.TaintValueDataflowFactory;

/**
 * @author Igor Konnov
 */
public class EngineRegistrar implements IAnalysisEngineRegistrar {
    private static IMethodAnalysisEngine<?>[] methodAnalysisEngineList = {
            new TaintValueDataflowFactory(),
            new TaintnessDataflowFactory(),
            new StackDepthDataflowFactory()
    };

    private static final IDatabaseFactory<?>[] databaseFactoryList = {
            new ReflectionDatabaseFactory<TaintAnnotationDatabase>(TaintAnnotationDatabase.class),
            new ReflectionDatabaseFactory<KeyIndicatorAnnotationDatabase>(KeyIndicatorAnnotationDatabase.class),
            new ReflectionDatabaseFactory<IsResultTaintedPropertyDatabase>(IsResultTaintedPropertyDatabase.class),
            new ReflectionDatabaseFactory<ParameterTaintnessPropertyDatabase>(ParameterTaintnessPropertyDatabase.class),
            new ReflectionDatabaseFactory<KeyIndicatorPropertyDatabase>(KeyIndicatorPropertyDatabase.class)
    };

    public void registerAnalysisEngines(IAnalysisCache analysisCache) {
        for (IDatabaseFactory<?> engine : databaseFactoryList) {
            engine.registerWith(analysisCache);
        }

        for (IMethodAnalysisEngine<?> engine : methodAnalysisEngineList) {
            engine.registerWith(analysisCache);
        }
    }
}
