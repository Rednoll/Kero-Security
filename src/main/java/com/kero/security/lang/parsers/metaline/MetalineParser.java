package com.kero.security.lang.parsers.metaline;

import com.kero.security.lang.TokensSequence;
import com.kero.security.lang.nodes.metaline.MetalineNode;

public interface MetalineParser<T extends MetalineNode> {

	public boolean isMatch(TokensSequence tokens);
	public T parse(TokensSequence tokens);
}
