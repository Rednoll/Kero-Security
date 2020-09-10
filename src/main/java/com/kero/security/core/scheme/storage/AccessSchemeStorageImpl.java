package com.kero.security.core.scheme.storage;

import java.util.HashMap;

import com.kero.security.core.scheme.AccessScheme;

public class AccessSchemeStorageImpl extends HashMap<Class, AccessScheme> implements AccessSchemeStorage {
	
	@Override
	public void add(AccessScheme scheme) {
	
		this.put(scheme.getTypeClass(), scheme);
	}
	
	@Override
	public boolean has(Class<?> rawType) {
		
		return this.containsKey(rawType);
	}
	
	@Override
	public AccessScheme getByAliase(String aliase) {
		
		for(AccessScheme scheme : this.values()) {
			
			if(scheme.getAliase().equals(aliase)) {
				
				return scheme;
			}
		}
		
		return null;
	}
}
