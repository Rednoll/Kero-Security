package com.kero.security.core.config.action;

import java.lang.reflect.Method;

public interface Action {
	
	public static Action EMPTY = new Empty();
	
	public Object process(Method method, Object original, Object[] args);

	static class Empty implements Action {

		private Empty() {
			
		}
		
		@Override
		public Object process(Method method, Object original, Object[] args) {
			
			throw new RuntimeException("Runned EMPTY action. Your Kero-Security configuration is bad, if you see this exception.");
		}
	}
}