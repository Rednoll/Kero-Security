package com.kero.security.core.config.prepared;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Set;

import com.kero.security.core.managers.KeroAccessManager;
import com.kero.security.core.role.Role;
import com.kero.security.core.scheme.AccessScheme;

public class PreparedGrantRule extends PreparedActionBase implements PreparedAction {
	
	public PreparedGrantRule(AccessScheme scheme, Set<Role> roles) {
		super(scheme, roles);
	
	}

	@Override
	public Object process(Method method, Object original, Object[] args) {
		
		try {
		
			Object methodResult = method.invoke(original, args);
			Class<?> methodResultClass = methodResult.getClass();
			
			if(Modifier.isFinal(methodResultClass.getModifiers())) {
				
				return methodResult;
			}
			
			KeroAccessManager manager = this.scheme.getManager();
			
			methodResult = manager.protect(methodResult, this.roles);

			return methodResult;
		}
		catch(Exception e) {
			
			throw new RuntimeException(e);
		}
	}
}
