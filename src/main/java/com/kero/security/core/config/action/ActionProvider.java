package com.kero.security.core.config.action;

import java.util.Collection;

import com.kero.security.core.role.Role;
import com.kero.security.core.scheme.AccessScheme;

public interface ActionProvider {

	public Action prepare(AccessScheme scheme, Collection<Role> propagatedRoles);
}
