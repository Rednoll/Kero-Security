package com.kero.security.core.lang.lexems;

import com.kero.security.core.lang.tokens.PropertyToken;

public class PropertyLexem extends KsdlProtectedUnitLexem<PropertyToken> {

	public PropertyLexem() {
		super("[A-z]+[A-z_0-9]*(\\([GF]\\))*:*");
	
	}

	@Override
	public PropertyToken tokenize(String data) {
	
		String rawName = data;
		Boolean defaultAccessible = null;
		
		if(rawName.contains("(")) {
			
			rawName = rawName.substring(0, rawName.indexOf("("));
			
			if(data.matches("\\(G\\)")) {
				
				defaultAccessible = true;
			}
			else if(data.matches("\\(F\\)")) {
				
				defaultAccessible = false;
			}
		}
		else if(rawName.contains(":")) {
			
			rawName = rawName.substring(0, rawName.indexOf(":"));
		}
		
		return new PropertyToken(rawName, defaultAccessible);
	}
}
