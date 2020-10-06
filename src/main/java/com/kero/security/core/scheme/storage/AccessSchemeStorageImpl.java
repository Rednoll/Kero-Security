package com.kero.security.core.scheme.storage;

import java.util.HashMap;

import com.kero.security.core.scheme.AccessScheme;

public class AccessSchemeStorageImpl extends HashMap<Class<?>, AccessScheme> implements AccessSchemeStorage {
	
	private static final long serialVersionUID = 1L;

	@Override
	public void add(AccessScheme scheme) {
	
		this.put(scheme.getTypeClass(), scheme);
	}
	
	@Override
	public boolean has(Class<?> rawType) {
		
		return this.containsKey(rawType);
	}
	
	@Override
	public AccessScheme getByName(String name) {
		
		for(AccessScheme scheme : this.values()) {
			
			if(scheme.getName().equals(name)) {
				
				return scheme;
			}
		}
		
		return null;
	}
}
