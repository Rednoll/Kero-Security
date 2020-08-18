package com.kero.security.core.rules;

import java.util.Collections;
import java.util.Objects;
import java.util.Set;

import com.kero.security.core.config.prepared.PreparedAction;
import com.kero.security.core.config.prepared.PreparedDenyRule;
import com.kero.security.core.config.prepared.PreparedGrantRule;
import com.kero.security.core.role.Role;
import com.kero.security.core.scheme.AccessScheme;

public class AccessRuleImpl implements AccessRule {

	private Set<Role> roles;
	private boolean accessible;
	
	public AccessRuleImpl(Set<Role> roles, boolean accessible) {
		
		this.roles = roles;
		this.accessible = accessible;
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
	public PreparedAction prepare(AccessScheme scheme, Set<Role> roles) {
		
		if(this.accessible(roles)) {
			
			return new PreparedGrantRule(scheme, roles);
		}
		else {
			
			return new PreparedDenyRule(scheme, roles);
		}
	}
	
	@Override
	public boolean manage(Set<Role> roles) {
		
		return !Collections.disjoint(this.roles, roles);
	}
	
	@Override
	public boolean accessible(Set<Role> roles) {
		
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
	
	public Set<Role> getRoles() {
		
		return this.roles;
	}
}
