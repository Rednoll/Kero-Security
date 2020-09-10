package com.kero.security.core.scheme;

import java.util.Map;

import com.kero.security.core.KeroAccessAgent;
import com.kero.security.core.property.Property;

public class InterfaceAccessScheme extends AccessSchemeBase {

	public InterfaceAccessScheme() {
		super();
		
	}
	
	public InterfaceAccessScheme(KeroAccessAgent agent, Class<?> type) {
		super(agent, type);
		
	}

	public InterfaceAccessScheme(KeroAccessAgent agent, String aliase, Class<?> type) {
		super(agent, aliase, type);
		
	}
	
	public void collectProperties(Map<String, Property> complexProperties) {
		
		collectLocalProperties(complexProperties);
		
		if(this.inherit) {
			
			collectFromInterfaces(complexProperties);
		}
	}
}