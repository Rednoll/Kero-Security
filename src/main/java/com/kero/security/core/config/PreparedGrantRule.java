package com.kero.security.core.config;

import java.lang.reflect.Method;

public class PreparedGrantRule implements PreparedAction {
	
	@Override
	public Object process(Method method, Object original, Object[] args) {
		
		try {
		
			return method.invoke(original, args);
		}
		catch(Exception e) {
			
			throw new RuntimeException(e);
		}
	}
}
