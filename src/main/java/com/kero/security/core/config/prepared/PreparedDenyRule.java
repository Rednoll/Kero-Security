package com.kero.security.core.config.prepared;

import java.lang.reflect.Method;

import com.kero.security.core.exception.AccessException;
import com.kero.security.core.scheme.AccessScheme;

public class PreparedDenyRule extends PreparedActionBase implements PreparedAction {

	public PreparedDenyRule(AccessScheme scheme) {
		super(scheme);
		
	}

	@Override
	public Object process(Method method, Object original, Object[] args) {
		
		throw new AccessException("Access denied for: "+scheme.getManager().extractName(method.getName()));
	}
}