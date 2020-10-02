package com.kero.security.core.rules;

import java.util.Collection;

import com.kero.security.core.config.prepared.PreparedAction;
import com.kero.security.core.role.Role;
import com.kero.security.core.scheme.AccessScheme;

public interface AccessRule {
	
	public static final AccessRule DENY_ALL = new AbsoluteAccessRule(false);
	public static final AccessRule GRANT_ALL = new AbsoluteAccessRule(true);
	
	public PreparedAction prepare(AccessScheme scheme, Collection<Role> roles);
	
	public boolean manage(Collection<Role> role);

	public boolean accessible(Collection<Role> roles);
	
	public Collection<Role> getRoles();
	
	public boolean isAllower();
	public boolean isDisallower();
}