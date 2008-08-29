package su.msu.cs.lvk.secbugs.annotations;

import javax.annotation.meta.TypeQualifier;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation of a method that possibly returns tainted data.
 *
 * @author Igor Konnov
 */
@Retention(RetentionPolicy.CLASS)
@Target(ElementType.METHOD)
@TypeQualifier
public @interface TaintedResult {
}
