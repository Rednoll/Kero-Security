package com.kero.security.core.config;

import java.lang.reflect.Method;
import java.util.function.Function;

public class PreparedInterceptedRule implements PreparedRule {

	private Function<Object, Object> interceptor;
	
	public PreparedInterceptedRule(Function<Object, Object> interceptor) {
	
		this.interceptor = interceptor;
	}
	
	@Override
	public Object process(Method method, Object original, Object[] args) {
		
		return interceptor.apply(original);
	}
}
