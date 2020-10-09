package com.kero.security.core.config;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;

public interface PreparedAccessConfiguration extends InvocationHandler {

	@Override
	public Object invoke(Object original, Method method, Object[] args);
}
