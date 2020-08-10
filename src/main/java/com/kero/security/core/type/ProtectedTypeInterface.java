package com.kero.security.core.type;

import java.util.List;
import java.util.Map;
import java.util.Set;

import com.kero.security.core.managers.KeroAccessManager;
import com.kero.security.core.property.Property;
import com.kero.security.core.role.Role;
import com.kero.security.core.rules.AccessRule;

public class ProtectedTypeInterface extends ProtectedTypeBase {

	public ProtectedTypeInterface() {
		super();
		
	}
	
	public ProtectedTypeInterface(KeroAccessManager manager, Class<?> type, AccessRule defaultRule) {
		super(manager, type, defaultRule);
		
	}

	public void collectRules(Map<String, Property> propertiesDict, Map<Property, List<AccessRule>> rules, Map<String, Set<Role>> processedRoles) {
		
		collectLocalRules(propertiesDict, rules, processedRoles);
		collectFromInterfaces(propertiesDict, rules, processedRoles);
	}
}