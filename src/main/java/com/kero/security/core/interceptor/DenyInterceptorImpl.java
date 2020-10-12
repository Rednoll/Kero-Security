package com.kero.security.core.interceptor;

import java.util.Set;
import java.util.function.BiFunction;

import com.kero.security.core.role.Role;
import com.kero.security.core.scheme.AccessScheme;

public class DenyInterceptorImpl extends DenyInterceptorBase {

	private BiFunction<Object, Object[], Object> function;
	
	public DenyInterceptorImpl() {}
	
	public DenyInterceptorImpl(AccessScheme scheme, Set<Role> roles, BiFunction<Object, Object[], Object> function) {
		super(scheme, roles);
		
		this.function = function;
	}
	
	@Override
	public Object intercept(Object original, Object[] args) {
		
		return function.apply(original, args);
	}
}
