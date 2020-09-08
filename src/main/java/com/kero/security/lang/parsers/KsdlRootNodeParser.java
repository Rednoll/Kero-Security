package com.kero.security.lang.parsers;

import com.kero.security.lang.collections.TokenSequence;
import com.kero.security.lang.nodes.KsdlNode;

public interface KsdlRootNodeParser<T extends KsdlNode> extends KsdlNodeParser<T> {

	public boolean isMatch(TokenSequence tokens);
}
