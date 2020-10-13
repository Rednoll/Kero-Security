package com.kero.security.core.config.action;

import java.lang.reflect.Method;
import java.util.Collection;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.config.action.exceptions.ActionGrantMethodInvokeException;
import com.kero.security.core.role.Role;
import com.kero.security.core.scheme.AccessScheme;

public class ActionGrant extends ActionBase implements Action {
	
	private Collection<Role> propagatedRoles;
	
	public ActionGrant(AccessScheme scheme, Collection<Role> propogatedRoles) {
		super(scheme);
	
		this.propagatedRoles = propogatedRoles;
	}

	@Override
	public Object process(Method method, Object original, Object[] args) {
		
		Object methodResult = null;
		
		try {
		
			methodResult = method.invoke(original, args);
		}
		catch(Exception e) {
			
			throw new ActionGrantMethodInvokeException(e);
		}
		
		KeroAccessAgent agent = this.scheme.getAgent();
		
		methodResult = agent.protect(methodResult, this.propagatedRoles);

		return methodResult;
	}
}
