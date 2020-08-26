package com.kero.security.core.lang.lexems;

import com.kero.security.core.lang.tokens.DefaultRuleToken;

public class DefaultRuleLexem extends KsdlLexemBase<DefaultRuleToken> {

	public DefaultRuleLexem() {
		super("\\([GD]\\)");
	
	}

	@Override
	public DefaultRuleToken tokenize(String data) {
				
		return new DefaultRuleToken(data.charAt(1) == 'G');
	}
}
