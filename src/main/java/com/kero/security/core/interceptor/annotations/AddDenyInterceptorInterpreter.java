package com.kero.security.core.interceptor.annotations;

import java.util.Set;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.annotations.PropertyAnnotationInterpreterBase;
import com.kero.security.core.interceptor.DenyInterceptor;
import com.kero.security.core.role.Role;
import com.kero.security.core.scheme.configuration.SinglePropertyConfigurator;

public class AddDenyInterceptorInterpreter extends PropertyAnnotationInterpreterBase<AddDenyInterceptor> {
	
	public AddDenyInterceptorInterpreter(KeroAccessAgent agent) {
		super(agent);
	
	}

	@Override
	public void interpret(SinglePropertyConfigurator configurator, AddDenyInterceptor annotation) {
		
		Set<Role> roles = this.agent.getOrCreateRole(annotation.roles());
		
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
			.addDenyInterceptor(interceptor);
	}
}
