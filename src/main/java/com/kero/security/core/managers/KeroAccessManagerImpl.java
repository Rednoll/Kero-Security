package com.kero.security.core.managers;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import com.kero.security.core.role.Role;
import com.kero.security.core.role.RoleImpl;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.rules.AccessRuleImpl;
import com.kero.security.core.type.ProtectedType;
import com.kero.security.core.type.ProtectedTypeClass;
import com.kero.security.core.type.ProtectedTypeInterface;

public class KeroAccessManagerImpl implements KeroAccessManager {
	
	protected Map<Class, ProtectedType> types = new HashMap<>();
	
	protected Map<String, Role> roles = new HashMap<>();
	
	protected AccessRule defaultRule = AccessRuleImpl.DENY_ALL;

	@Override
	public Role createRole(String name, int priority) {
		
		if(hasRoleWithPriority(priority)) throw new RuntimeException("Role with priority: "+priority+" already exists!");
		
		Role role = new RoleImpl(name, priority);
		
		roles.put(name, role);
		
		return role;
	}
	
	public Role getRole(String name) {
		
		return roles.get(name);
	}
	
	public Role getOrCreateRole(String name) {
		
		if(hasRole(name)) {
			
			return getRole(name);
		}
		else {
			
			Role withMaxPriority = getRoleWithMaxPriorty();
			int priority = withMaxPriority != null ? withMaxPriority.getPriority() + 1 : 1;
			
			return createRole(name, priority);
		}
	}
	
	public Role getRoleWithMaxPriorty() {
		
		Role role = null;
		int max = Integer.MIN_VALUE;
		
		for(Role suspect : roles.values()) {
			
			if(suspect.getPriority() > max) {
				
				role = suspect;
				max = suspect.getPriority();
			}
		}
		
		return role;
	}
	
	public boolean hasRole(String name) {
		
		return this.roles.containsKey(name);
	}
	
	public boolean hasRoleWithPriority(int priority) {
		
		for(Role role : roles.values()) {
			
			if(role.getPriority() == priority) {
				
				return true;
			}
		}
		
		return false;
	}
	
	@Override
	public boolean hasType(Class<?> rawType) {
		
		return types.containsKey(rawType);
	}

	@Override
	public ProtectedType getType(Class<?> rawType) {
		
		return types.get(rawType);
	}
	
	@Override
	public ObjectTypeAccessManager type(Class<?> rawType) {
		
		try {
			
			return new ObjectTypeAccessManager(this, getOrCreateType(rawType));
		}
		catch(Exception e) {
			
			throw new RuntimeException(e);
		}
	}
	
	public ProtectedType getOrCreateType(Class<?> rawType){
		
		return hasType(rawType) ? getType(rawType) : createType(rawType);
	}
	
	public ProtectedType createType(Class<?> rawType) {
		
		if(rawType.isInterface()) {
			
			types.put(rawType, new ProtectedTypeInterface(this, rawType, defaultRule));
		}
		else {
			
			try {
				
				types.put(rawType, new ProtectedTypeClass(this, rawType, defaultRule));
			}
			catch(Exception e) {
				
				throw new RuntimeException(e);
			}
		}
		
		return types.get(rawType);
	}
	
	@Override
	public <T> T protect(T object, Set<Role> roles) {
		
		try {
			
			ProtectedTypeClass protectedType = (ProtectedTypeClass) getOrCreateType(object.getClass());
				
			return protectedType.protect(object, roles);
		}
		catch(Exception e) {
			
			throw new RuntimeException(e);
		}
	}
	
	public AccessRule getDefaultRule() {
		
		return this.defaultRule;
	}
}
