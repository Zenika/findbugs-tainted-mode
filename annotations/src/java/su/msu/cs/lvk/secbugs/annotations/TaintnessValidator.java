package su.msu.cs.lvk.secbugs.annotations;

import javax.annotation.meta.TypeQualifier;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.annotation.ElementType;

/**
 * This annotation is applicable to validator function (boolean), that
 * should return true if parameter is untainted.
 * 
 * for example : javax.util.regex.Pattern.matcher(String).matches()
 *
 * @author Igor Konnov
 */
@Retention(RetentionPolicy.CLASS)
@Target(ElementType.METHOD)
@TypeQualifier
public @interface TaintnessValidator {
}
