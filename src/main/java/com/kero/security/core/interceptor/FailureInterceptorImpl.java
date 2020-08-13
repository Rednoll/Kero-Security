package com.kero.security.core.interceptor;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;

import com.kero.security.core.config.PreparedInterceptor;
import com.kero.security.core.role.Role;

public class FailureInterceptorImpl implements FailureInterceptor {

	private Set<Role> roles = new HashSet<>();
	
	private Function<Object, Object> function;
	
	public FailureInterceptorImpl() {}
	
	public FailureInterceptorImpl(Set<Role> roles, Function<Object, Object> function) {
	
		this.roles = roles;
		this.function = function;
	}
	
	@Override
	public PreparedInterceptor prepare(Set<Role> roles) {
		
		if(manage(roles) || this.roles.isEmpty()) {
		
			return new PreparedInterceptor(function);
		}
		else {
			
			String rolesMessage = "";
			
			for(Role role : roles) {
				
				rolesMessage += role.getName()+" ";
			}
			
			throw new RuntimeException("This interceptor not suitable for roles: ["+rolesMessage.trim()+"]");
		}
	}

	private boolean manage(Set<Role> roles) {
		
		return !Collections.disjoint(this.roles, roles);
	}
	
	@Override
	public Object intercept(Object obj) {
		
		return function.apply(obj);
	}

	@Override
	public Set<Role> getRoles() {
	
		return this.roles;
	}
}
