package com.kero.security.core.interceptor;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.kero.security.core.config.action.ActionInterceptor;
import com.kero.security.core.interceptor.exceptions.UnsuitableDenyInterceptorException;
import com.kero.security.core.role.Role;
import com.kero.security.core.scheme.AccessScheme;

public abstract class DenyInterceptorBase implements DenyInterceptor {
	
	private Set<Role> roles = new HashSet<>();
	private AccessScheme scheme;
	
	public DenyInterceptorBase() {}
	
	public DenyInterceptorBase(AccessScheme scheme, Set<Role> roles) {
	
		this.scheme = scheme;
		this.roles = roles;
	}
	
	@Override
	public ActionInterceptor prepare(Collection<Role> roles) {
		
		if(manageAny(roles) || this.roles.isEmpty()) {
		
			return new ActionInterceptor(this.scheme, this::intercept);
		}
		else {

			throw new UnsuitableDenyInterceptorException("This interceptor not suitable for roles: "+roles);
		}
	}

	private boolean manageAny(Collection<Role> roles) {
		
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
