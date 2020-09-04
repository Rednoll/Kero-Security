package com.kero.security.lang.lexems;

import com.kero.security.lang.tokens.KsdlToken;

public interface KsdlLexem<T extends KsdlToken> {

	public T tokenize(String data);
	public boolean isMatch(CharSequence data);
	public String getPattern();
}
