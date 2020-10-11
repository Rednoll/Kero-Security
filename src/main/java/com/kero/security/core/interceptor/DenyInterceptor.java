package com.kero.security.core.interceptor;

import java.util.Collection;
import java.util.Set;

import com.kero.security.core.config.action.ActionInterceptor;
import com.kero.security.core.role.Role;

public interface DenyInterceptor {

	public ActionInterceptor prepare(Collection<Role> roles);
	public Object intercept(Object obj);
	
	public void setRoles(Set<Role> roles);
	public Set<Role> getRoles();
}
