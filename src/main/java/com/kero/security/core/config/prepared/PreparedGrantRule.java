package com.kero.security.core.config.prepared;

import java.lang.reflect.Method;
import java.util.Set;

import com.kero.security.core.role.Role;
import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.managers.KeroAccessManager;

public class PreparedGrantRule extends PreparedActionBase implements PreparedAction {
	
	private Set<Role> propagatedRoles;
	
	public PreparedGrantRule(AccessScheme scheme, Set<Role> propogatedRoles) {
		super(scheme);
	
		this.propagatedRoles = propogatedRoles;
	}

	@Override
	public Object process(Method method, Object original, Object[] args) {
		
		try {
		
			Object methodResult = method.invoke(original, args);
			
			KeroAccessManager manager = this.scheme.getManager();
			
			methodResult = manager.protect(methodResult, this.propagatedRoles);

			return methodResult;
		}
		catch(Exception e) {
			
			throw new RuntimeException(e);
		}
	}
}
