package com.kero.security.core.config.action;

import java.lang.reflect.Method;
import java.util.function.BiFunction;

import com.kero.security.core.scheme.AccessScheme;

public class ActionInterceptor extends ActionBase implements Action {

	private BiFunction<Object, Object[], Object> interceptor;
	
	public ActionInterceptor(AccessScheme scheme, BiFunction<Object, Object[], Object> interceptor) {
		super(scheme);
		
		this.interceptor = interceptor;
	}
	
	@Override
	public Object process(Method method, Object original, Object[] args) {
		
		
		return interceptor.apply(original, args);
	}
}
