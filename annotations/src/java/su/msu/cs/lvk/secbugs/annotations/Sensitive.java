package su.msu.cs.lvk.secbugs.annotations;

import javax.annotation.meta.TypeQualifier;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation for parameters of sensitive methods : should not be tainted
 * 
 * @author Igor Konnov
 */
@Retention(RetentionPolicy.CLASS)
@Target(ElementType.PARAMETER)
@TypeQualifier
public @interface Sensitive {
}
