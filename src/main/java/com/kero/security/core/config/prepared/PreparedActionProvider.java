package com.kero.security.core.config.prepared;

import java.util.Collection;

import com.kero.security.core.role.Role;
import com.kero.security.core.scheme.AccessScheme;

public interface PreparedActionProvider {

	public PreparedAction prepare(AccessScheme scheme, Collection<Role> propagatedRoles);
}
