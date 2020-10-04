package com.kero.security.core.scheme.storage;

import java.util.Map;

import com.kero.security.core.scheme.AccessScheme;

public interface AccessSchemeStorage extends Map<Class<?>, AccessScheme> {

	public void add(AccessScheme scheme);
	
	public boolean has(Class<?> rawType);
	
	public AccessScheme getByAliase(String aliase);
	
	public static AccessSchemeStorage create() {
		
		return new AccessSchemeStorageImpl();
	}
}
