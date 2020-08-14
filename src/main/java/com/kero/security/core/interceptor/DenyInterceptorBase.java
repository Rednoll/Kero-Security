package com.kero.security.core.interceptor;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.kero.security.core.config.PreparedInterceptor;
import com.kero.security.core.role.Role;

public abstract class DenyInterceptorBase implements DenyInterceptor {
	
	private Set<Role> roles = new HashSet<>();
	
	public DenyInterceptorBase() {}
	
	public DenyInterceptorBase(Set<Role> roles) {
	
		this.roles = roles;
	}
	
	@Override
	public PreparedInterceptor prepare(Set<Role> roles) {
		
		if(manage(roles) || this.roles.isEmpty()) {
		
			return new PreparedInterceptor(this::intercept);
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

	public void setRoles(Set<Role> roles) {
		
		this.roles = roles;
	}
	
	@Override
	public Set<Role> getRoles() {
	
		return this.roles;
	}
}
