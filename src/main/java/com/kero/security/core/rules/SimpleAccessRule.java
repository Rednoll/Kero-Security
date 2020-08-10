package com.kero.security.core.rules;

import java.util.Collections;
import java.util.Set;
import java.util.function.Function;

import com.kero.security.core.role.Role;

public class SimpleAccessRule implements AccessRule {

	public static final SimpleAccessRule DENY_ALL = new SimpleAccessRule(Collections.EMPTY_SET, true, null);
	public static final SimpleAccessRule GRANT_ALL = new SimpleAccessRule(Collections.EMPTY_SET, false, null);
	
	private Set<Role> roles;
	private boolean accessible;
	private Function<Object, Object> silentInterceptor;
	
	public SimpleAccessRule(Set<Role> roles, boolean accessible, Function<Object, Object> silentInterceptor) {
		
		this.roles = roles;
		this.accessible = accessible;
		this.silentInterceptor = silentInterceptor;
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
