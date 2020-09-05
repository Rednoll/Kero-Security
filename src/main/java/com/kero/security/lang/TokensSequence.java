package com.kero.security.lang;

import java.util.LinkedList;

import com.kero.security.lang.tokens.KsdlToken;

public class TokensSequence extends LinkedList<KsdlToken> {

	public <T extends KsdlToken> T tryGetOrDefault(T def) {
		
		return tryGetOrDefault((Class<T>) def.getClass(), def);
	}
	
	public <T extends KsdlToken> T tryGetOrDefault(Class<T> tokenClass, T def) {
		
		if(!isToken(0, tokenClass)) return def;
	
		return (T) poll();
	}
	
	public boolean isToken(int index, KsdlToken token) {
		
		return get(index) == token;
	}
	
	public boolean isToken(int index, Class<? extends KsdlToken> tokenClass) {
		
		return tokenClass.isAssignableFrom(get(index).getClass());
	}
}
