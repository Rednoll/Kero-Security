package com.kero.security.core.managers;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import com.kero.security.core.role.Role;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.rules.SimpleAccessRule;
import com.kero.security.core.type.ProtectedType;
import com.kero.security.core.type.ProtectedTypeClass;
import com.kero.security.core.type.ProtectedTypeInterface;

public class KeroAccessManagerImpl implements KeroAccessManager {
	
	private Map<Class, ProtectedType> types = new HashMap<>();
	
	private AccessRule defaultRule = SimpleAccessRule.DENY_ALL;

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
			
			return new ObjectTypeAccessManager(createOrGetType(rawType));
		}
		catch(Exception e) {
			
			throw new RuntimeException(e);
		}
	}
	
	public ProtectedType createOrGetType(Class<?> rawType) {
		
		return hasType(rawType) ? getType(rawType) : createType(rawType);
	}
	
	public ProtectedType createType(Class<?> rawType) {
		
		if(rawType.isInterface()) {
			
			types.put(rawType, new ProtectedTypeInterface(this, rawType, defaultRule));
		}
		else {
			
			types.put(rawType, new ProtectedTypeClass(this, rawType, defaultRule));
		}
		
		return types.get(rawType);
	}
	
	@Override
	public <T> T protect(T object, Set<Role> roles) {
		
		ProtectedTypeClass protectedType = (ProtectedTypeClass) createOrGetType(object.getClass());
		
		try {
			
			return protectedType.protect(object, roles);
		}
		catch(Exception e) {
			
			throw new RuntimeException(e);
		}
	}
	
	/*
	@Override
	public <T> T protect(T object, Set<Role> roles) {
		
		//TODO: ADD AUTO REGISTER NOT DECLARED TYPES
		
		try {
		
			Class<?> objectClass = object.getClass();
	
			return (T) ((ProtectedClassType) types.get(objectClass)).protect(object, roles);
		}
		catch(Exception e) {
			
			throw new RuntimeException(e);
		}
	}
	*/
}
