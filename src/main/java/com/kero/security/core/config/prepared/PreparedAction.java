package com.kero.security.core.config.prepared;

import java.lang.reflect.Method;

public interface PreparedAction {
	
	public Object process(Method method, Object original, Object[] args);
}