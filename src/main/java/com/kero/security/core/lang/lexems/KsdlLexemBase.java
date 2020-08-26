package com.kero.security.core.lang.lexems;

import java.util.regex.Pattern;

import com.kero.security.core.lang.tokens.KsdlToken;

public abstract class KsdlLexemBase<T extends KsdlToken> implements KsdlLexem<T> {

	private String pattern;
	
	public KsdlLexemBase(String pattern) {
		
		this.pattern = pattern;
	}
	
	@Override
	public boolean isMatch(CharSequence data) {
		
		return Pattern.matches(pattern, data);
	}
	
	@Override
	public String getPattern() {
		
		return this.pattern;
	}
}
