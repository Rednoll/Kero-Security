package com.kero.security.core.config;

import java.lang.reflect.Method;

public interface PreparedAction {
	
	public Object process(Method method, Object original, Object[] args);
}