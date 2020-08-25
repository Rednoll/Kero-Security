package com.kero.security.core.lang.lexems;

import com.kero.security.core.lang.tokens.TypeToken;

public class TypeLexem extends KsdlProtectedUnitLexem<TypeToken> {

	public TypeLexem() {
		super("(protect) [A-z]+[A-z_0-9]*(\\([GF]\\))*:*");
	
	}

	@Override
	public TypeToken tokenize(String data) {
		
		String rawName = data.substring("protect ".length());
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
		
		return new TypeToken(rawName, defaultAccessible);
	}
}
