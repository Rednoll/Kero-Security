package com.kero.security.core.type;

import java.lang.reflect.Method;
import java.util.Set;

import com.kero.security.core.managers.KeroAccessManager;
import com.kero.security.core.role.Role;
import com.kero.security.core.rules.AccessRule;

public class ProtectedInterfaceType extends ProtectedTypeBase implements ProtectedType {

	public ProtectedInterfaceType() {
		
	}
	
	public ProtectedInterfaceType(KeroAccessManager accessManager, Class<?> type, AccessRule defaultRule) throws Exception {
		super(accessManager, type, defaultRule);
		
	}
	
	@Override
	public Object tryInvoke(Object target, Method method, Object[] args, Set<Role> roles) throws Exception {
		
		return null;
	}
}
