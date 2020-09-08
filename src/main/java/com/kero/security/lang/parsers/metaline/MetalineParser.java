package com.kero.security.lang.parsers.metaline;

import com.kero.security.lang.collections.TokenSequence;
import com.kero.security.lang.nodes.metaline.MetalineNode;

public interface MetalineParser<T extends MetalineNode> {

	public boolean isMatch(TokenSequence tokens);
	public T parse(TokenSequence tokens);
}
