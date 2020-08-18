package com.kero.security.core.rules;

import java.util.Collections;
import java.util.Set;

import com.kero.security.core.config.prepared.PreparedAction;
import com.kero.security.core.role.Role;
import com.kero.security.core.scheme.AccessScheme;

public interface AccessRule {
	
	public static final AccessRuleImpl DENY_ALL = new AccessRuleImpl(Collections.EMPTY_SET, true);
	public static final AccessRuleImpl GRANT_ALL = new AccessRuleImpl(Collections.EMPTY_SET, false);
	
	public PreparedAction prepare(AccessScheme scheme, Set<Role> roles);
	
	public boolean manage(Set<Role> role);

	public boolean accessible(Set<Role> roles);
	
	public Set<Role> getRoles();
	
	public boolean isAllower();
	public boolean isDisallower();
}