package com.kero.security.core.interceptor.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import com.kero.security.core.interceptor.DenyInterceptor;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD, ElementType.METHOD})
public @interface DenyWithInterceptor {

	Class<? extends DenyInterceptor> value();
	String[] roles() default {};
}
