package com.kero.security.core.rules;

import java.util.Collection;
import java.util.Collections;

import com.kero.security.core.config.prepared.PreparedAction;
import com.kero.security.core.config.prepared.PreparedDenyRule;
import com.kero.security.core.config.prepared.PreparedGrantRule;
import com.kero.security.core.role.Role;
import com.kero.security.core.scheme.AccessScheme;

public class AbsoluteAccessRule implements AccessRule {

	private boolean isAllower;
	
	public AbsoluteAccessRule(boolean isAllower) {
		
		this.isAllower = isAllower;
	}
	
	@Override
	public PreparedAction prepare(AccessScheme scheme, Collection<Role> propagatedRoles) {
		
		if(this.isAllower) {
			
			return new PreparedGrantRule(scheme, propagatedRoles);
		}
		else {
		
			return new PreparedDenyRule(scheme);
		}
	}

	@Override
	public boolean manage(Collection<Role> role) {
		
		return false;
	}

	@Override
	public boolean accessible(Collection<Role> roles) {
		
		return isAllower;
	}

	@Override
	public Collection<Role> getRoles() {
		
		return Collections.EMPTY_SET;
	}

	@Override
	public boolean isAllower() {
		
		return this.isAllower;
	}

	@Override
	public boolean isDisallower() {
		
		return !this.isAllower;
	}
}
