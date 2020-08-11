package com.kero.security.core.config;

import java.lang.reflect.Method;

public interface PreparedAccessConfiguration {

	public Object process(Object original, Method method, Object[] args);
}
