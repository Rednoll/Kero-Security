package com.kero.security.core.rules.def;

import java.util.Collection;

import com.kero.security.core.config.prepared.PreparedAction;
import com.kero.security.core.config.prepared.PreparedDenyRule;
import com.kero.security.core.role.Role;
import com.kero.security.core.scheme.AccessScheme;

public class DefaultDenyRule implements DefaultAccessRule {

	@Override
	public PreparedAction prepare(AccessScheme scheme, Collection<Role> propagatedRoles) {
		
		return new PreparedDenyRule(scheme);
	}
}
