package com.kero.security.core.interceptor;

import java.util.Set;
import java.util.function.Function;

import com.kero.security.core.role.Role;
import com.kero.security.core.scheme.AccessScheme;

public class DenyInterceptorImpl extends DenyInterceptorBase {

	private Function<Object, Object> function;
	
	public DenyInterceptorImpl() {}
	
	public DenyInterceptorImpl(AccessScheme scheme, Set<Role> roles, Function<Object, Object> function) {
		super(scheme, roles);
		
		this.function = function;
	}

	
	@Override
	public Object intercept(Object obj) {
		
		return function.apply(obj);
	}
}
