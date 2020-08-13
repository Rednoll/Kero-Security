package com.kero.security.core.config;

import java.lang.reflect.Method;

import com.kero.security.core.exception.AccessException;

public class PreparedDenyRule implements PreparedAction {

	@Override
	public Object process(Method method, Object original, Object[] args) {
		
		throw new AccessException("Access denied for: "+method.getName());
	}
}