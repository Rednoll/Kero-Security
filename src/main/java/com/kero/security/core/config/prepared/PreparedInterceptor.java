package com.kero.security.core.config.prepared;

import java.lang.reflect.Method;
import java.util.Set;
import java.util.function.Function;

import com.kero.security.core.role.Role;
import com.kero.security.core.scheme.AccessScheme;

public class PreparedInterceptor extends PreparedActionBase implements PreparedAction {

	private Function<Object, Object> interceptor;
	
	public PreparedInterceptor(AccessScheme scheme, Set<Role> roles, Function<Object, Object> interceptor) {
		super(scheme, roles);
		
		this.interceptor = interceptor;
	}
	
	@Override
	public Object process(Method method, Object original, Object[] args) {
		
		return interceptor.apply(original);
	}
}
