package com.kero.security.core.rules.def;

import java.util.Collection;

import com.kero.security.core.config.prepared.PreparedAction;
import com.kero.security.core.config.prepared.PreparedGrantRule;
import com.kero.security.core.role.Role;
import com.kero.security.core.scheme.AccessScheme;

public class DefaultGrantRule implements DefaultAccessRule {

	@Override
	public PreparedAction prepare(AccessScheme scheme, Collection<Role> propagatedRoles) {
		
		return new PreparedGrantRule(scheme, propagatedRoles);
	}
}
