package com.kero.security.core.interceptor;

import java.util.Set;
import java.util.function.Function;

import com.kero.security.core.role.Role;

public class DenyInterceptorImpl extends DenyInterceptorBase {

	private Function<Object, Object> function;
	
	public DenyInterceptorImpl() {}
	
	public DenyInterceptorImpl(Set<Role> roles, Function<Object, Object> function) {
		super(roles);
		
		this.function = function;
	}

	
	@Override
	public Object intercept(Object obj) {
		
		return function.apply(obj);
	}
}
