package com.kero.security.lang.parsers;

import com.kero.security.lang.TokensSequence;
import com.kero.security.lang.nodes.KsdlNode;

public interface KsdlRootNodeParser<T extends KsdlNode> extends KsdlNodeParser<T> {

	public boolean isMatch(TokensSequence tokens);
}
