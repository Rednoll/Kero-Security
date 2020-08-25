package com.kero.security.core.lang.lexems;

import com.kero.security.core.lang.tokens.KsdlToken;

public abstract class KsdlProtectedUnitLexem<T extends KsdlToken> extends KsdlLexemBase<T> {

	public KsdlProtectedUnitLexem(String pattern) {
		super(pattern);
	
	}
}
