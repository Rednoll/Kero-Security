package com.kero.security.lang.parsers;

import com.kero.security.lang.TokensSequence;
import com.kero.security.lang.nodes.KsdlNode;

public interface KsdlNodeParser<T extends KsdlNode> {

	public T parse(TokensSequence tokens);
}
