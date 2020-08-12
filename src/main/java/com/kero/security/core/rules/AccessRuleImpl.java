package com.kero.security.core.rules;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;

import com.kero.security.core.config.PreparedDenyRule;
import com.kero.security.core.config.PreparedGrantRule;
import com.kero.security.core.config.PreparedInterceptedRule;
import com.kero.security.core.config.PreparedRule;
import com.kero.security.core.exception.AccessException;
import com.kero.security.core.role.Role;

public class AccessRuleImpl implements AccessRule {

	private Set<Role> roles;
	private boolean accessible;
	private Function<Object, Object> silentInterceptor;
	
	public AccessRuleImpl(Set<Role> roles, boolean accessible, Function<Object, Object> silentInterceptor) {
		
		this.roles = roles;
		this.accessible = accessible;
		this.silentInterceptor = silentInterceptor;
	}
	
	@Override
	public int hashCode() {
		
		return Objects.hash(accessible, roles, silentInterceptor);
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
		return accessible == other.accessible && Objects.equals(roles, other.roles)
				&& Objects.equals(silentInterceptor, other.silentInterceptor);
	}
	
	public Object process(Object original, Method method, Object[] args, Set<Role> roles) throws Exception {

		if(this.accessible(roles)) {
			
			return method.invoke(original, args);
		}
		else if(this.hasSilentInterceptor()) {
			
			return this.processSilentInterceptor(original);
		}
		else {
			
			throw new AccessException("Access denied for: "+method.getName()+"!");
		}
	}
	
	@Override
	public PreparedRule prepare(Set<Role> roles) {
		
		if(this.accessible(roles)) {
			
			return new PreparedGrantRule();
		}
		else if(this.hasSilentInterceptor()) {
			
			return new PreparedInterceptedRule(this.silentInterceptor);
		}
		else {
			
			return new PreparedDenyRule();
		}
	}

	@Override
	public boolean isSimple() {
		
		return !hasSilentInterceptor();
	}
	
	@Override
	public Role getHighestPriorityRole() {
		
		int max = -1;
		Role maxPriorityRole = null;
		
		for(Role suspect : roles) {
			
			if(suspect.getPriority() > max) {
				
				maxPriorityRole = suspect;
				max = suspect.getPriority();
			}
		}
		
		return maxPriorityRole;
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
	
	public boolean hasSilentInterceptor() {
		
		return silentInterceptor != null;
	}
	
	@Override
	public Object processSilentInterceptor(Object target) {
		
		return silentInterceptor.apply(target);
	}
	
	public Set<Role> getRoles() {
		
		return this.roles;
	}
}
