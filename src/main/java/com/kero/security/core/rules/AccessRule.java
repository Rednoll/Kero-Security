package com.kero.security.core.rules;

import java.util.Collection;
import java.util.Collections;

import com.kero.security.core.config.prepared.PreparedAction;
import com.kero.security.core.role.Role;
import com.kero.security.core.scheme.AccessScheme;

public interface AccessRule {
	
	public static final AccessRuleImpl DENY_ALL = new AccessRuleImpl(Collections.EMPTY_SET, true);
	public static final AccessRuleImpl GRANT_ALL = new AccessRuleImpl(Collections.EMPTY_SET, false);
	
	public PreparedAction prepare(AccessScheme scheme, Collection<Role> roles);
	
	public boolean manage(Collection<Role> role);

	public boolean accessible(Collection<Role> roles);
	
	public Collection<Role> getRoles();
	
	public boolean isAllower();
	public boolean isDisallower();
}