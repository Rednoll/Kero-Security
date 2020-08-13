package com.kero.security.core.config;

import java.lang.reflect.Method;
import java.util.function.Function;

public class PreparedInterceptor implements PreparedAction {

	private Function<Object, Object> interceptor;
	
	public PreparedInterceptor(Function<Object, Object> interceptor) {
	
		this.interceptor = interceptor;
	}
	
	@Override
	public Object process(Method method, Object original, Object[] args) {
		
		return interceptor.apply(original);
	}
}
