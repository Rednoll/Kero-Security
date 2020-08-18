package com.kero.security.core.interceptor;

import java.util.Set;

import com.kero.security.core.config.prepared.PreparedInterceptor;
import com.kero.security.core.role.Role;

public interface DenyInterceptor {

	public PreparedInterceptor prepare(Set<Role> roles);
	public Object intercept(Object obj);
	
	public void setRoles(Set<Role> roles);
	public Set<Role> getRoles();
}
