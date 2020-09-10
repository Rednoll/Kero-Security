package com.kero.security.core.rules;

import java.util.Collection;
import java.util.Collections;
import java.util.Objects;

import com.kero.security.core.config.prepared.PreparedAction;
import com.kero.security.core.config.prepared.PreparedDenyRule;
import com.kero.security.core.config.prepared.PreparedGrantRule;
import com.kero.security.core.role.Role;
import com.kero.security.core.scheme.AccessScheme;

public class AccessRuleImpl implements AccessRule {

	private Collection<Role> roles;
	private boolean accessible;
	
	public AccessRuleImpl(Collection<Role> roles, boolean accessible) {
		
		this.roles = roles;
		this.accessible = accessible;
	}
	
	@Override
	public String toString() {
		return "AccessRuleImpl [roles=" + roles + ", accessible=" + accessible + "]";
	}

	@Override
	public int hashCode() {
		
		return Objects.hash(accessible, roles);
	}

	@Override
	public boolean equals(Object obj) {
		
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		AccessRuleImpl other = (AccessRuleImpl) obj;
		return accessible == other.accessible && Objects.equals(roles, other.roles);
	}
	
	@Override
	public PreparedAction prepare(AccessScheme scheme, Collection<Role> propagatedRoles) {
		
		if(this.accessible(roles)) {
			
			return new PreparedGrantRule(scheme, propagatedRoles);
		}
		else {
			
			return new PreparedDenyRule(scheme);
		}
	}
	
	@Override
	public boolean manage(Collection<Role> roles) {
		
		return !Collections.disjoint(this.roles, roles);
	}
	
	@Override
	public boolean accessible(Collection<Role> roles) {
		
		return Collections.disjoint(this.roles, roles) ? !this.accessible : this.accessible;
	}

	@Override
	public boolean isAllower() {
		
		return this.accessible;
	}

	@Override
	public boolean isDisallower() {
		
		return !this.accessible;
	}
	
	public Collection<Role> getRoles() {
		
		return this.roles;
	}
}
