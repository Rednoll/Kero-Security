package com.kero.security.core.config.action;

import java.lang.reflect.Method;
import java.util.function.Function;

import com.kero.security.core.scheme.AccessScheme;

public class ActionInterceptor extends ActionBase implements Action {

	private Function<Object, Object> interceptor;
	
	public ActionInterceptor(AccessScheme scheme, Function<Object, Object> interceptor) {
		super(scheme);
		
		this.interceptor = interceptor;
	}
	
	@Override
	public Object process(Method method, Object original, Object[] args) {
		
		return interceptor.apply(original);
	}
}
