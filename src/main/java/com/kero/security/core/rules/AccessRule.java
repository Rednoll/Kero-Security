package com.kero.security.core.rules;

import java.util.Collections;
import java.util.Set;

import com.kero.security.core.config.PreparedAction;
import com.kero.security.core.role.Role;

public interface AccessRule {
	
	public static final AccessRuleImpl DENY_ALL = new AccessRuleImpl(Collections.EMPTY_SET, true);
	public static final AccessRuleImpl GRANT_ALL = new AccessRuleImpl(Collections.EMPTY_SET, false);
	
	public PreparedAction prepare(Set<Role> roles);
	
	public boolean manage(Set<Role> role);

	public boolean accessible(Set<Role> roles);
	
	public Set<Role> getRoles();
	
	public boolean isAllower();
	public boolean isDisallower();
}