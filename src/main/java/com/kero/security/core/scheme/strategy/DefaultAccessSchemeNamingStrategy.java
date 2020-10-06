package com.kero.security.core.scheme.strategy;

public class DefaultAccessSchemeNamingStrategy implements AccessSchemeNamingStrategy {

	@Override
	public String getName(Class<?> rawType) {
		
		return rawType.getSimpleName();
	}
}
