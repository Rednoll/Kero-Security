package com.kero.security.core.interceptor.annotations;

import java.util.Set;

import com.kero.security.core.KeroAccessManager;
import com.kero.security.core.annotations.PropertyAnnotationInterpreterBase;
import com.kero.security.core.interceptor.DenyInterceptor;
import com.kero.security.core.role.Role;
import com.kero.security.core.scheme.configuration.SinglePropertyConfigurator;

public class DenyWithInterceptorInterpreter extends PropertyAnnotationInterpreterBase<DenyWithInterceptor> {

	public DenyWithInterceptorInterpreter(KeroAccessManager manager) {
		super(manager);
	
	}

	@Override
	public void interpret(SinglePropertyConfigurator configurator, DenyWithInterceptor annotation) {
		
		Set<Role> roles = this.manager.getOrCreateRole(annotation.roles());
		
		Class<? extends DenyInterceptor> interceptorClass = annotation.value();
		
		DenyInterceptor interceptor;
		
		try {
			
			interceptor = interceptorClass.getConstructor().newInstance();
		}
		catch(Exception e) {
			
			throw new RuntimeException(e);
		}
		
		interceptor.setRoles(roles);
		
		configurator
			.denyWithInterceptor(interceptor);
	}
}
