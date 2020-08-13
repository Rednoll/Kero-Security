package com.kero.security.core.type;

import java.util.Map;

import com.kero.security.core.managers.KeroAccessManager;
import com.kero.security.core.property.Property;

public class ProtectedTypeInterface extends ProtectedTypeBase {

	public ProtectedTypeInterface() {
		super();
		
	}
	
	public ProtectedTypeInterface(KeroAccessManager manager, Class<?> type) {
		super(manager, type);
		
	}
	
	public void collectProperties(Map<String, Property> complexProperties) {
		
		collectLocalProperties(complexProperties);
		
		if(this.inherit) {
			
			collectFromInterfaces(complexProperties);
		}
	}
}