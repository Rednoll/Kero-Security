package com.kero.security.core.rules;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.Set;

import com.kero.security.core.config.PreparedRule;
import com.kero.security.core.role.Role;

public interface AccessRule {
	
	public static final AccessRuleImpl DENY_ALL = new AccessRuleImpl(Collections.EMPTY_SET, true, null);
	public static final AccessRuleImpl GRANT_ALL = new AccessRuleImpl(Collections.EMPTY_SET, false, null);
	
	public Object process(Object original, Method method, Object[] args, Set<Role> roles) throws Exception;
	public PreparedRule prepare(Set<Role> roles);
	
	public Role getHighestPriorityRole();
	
	public boolean manage(Set<Role> role);

	public boolean accessible(Set<Role> roles);

	public boolean hasSilentInterceptor();
	public Object processSilentInterceptor(Object target);
	
	public Set<Role> getRoles();
	
	public boolean isAllower();
	public boolean isDisallower();
	
	
	/**
	 * Simple access rule doesn't ANY additions like interceptor. It's manages only grant/deny functions.
	 */
	public boolean isSimple();
}