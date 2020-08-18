package com.kero.security.core.config.prepared;

import java.util.Set;

import com.kero.security.core.role.Role;
import com.kero.security.core.scheme.AccessScheme;

public abstract class PreparedActionBase implements PreparedAction {

	protected AccessScheme scheme;
	protected Set<Role> roles;
	
	public PreparedActionBase(AccessScheme scheme, Set<Role> roles) {
		
		this.roles = roles;
		this.scheme = scheme;
	}
}
