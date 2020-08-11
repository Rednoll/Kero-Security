package com.kero.security.core.config;

import java.lang.reflect.Method;

public interface PreparedRule {
	
	public Object process(Method method, Object original, Object[] args);
}