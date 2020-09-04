package com.kero.security.lang.parsers.metaline;

import java.util.List;
import java.util.Queue;

import com.kero.security.lang.nodes.metaline.MetalineNode;
import com.kero.security.lang.tokens.KsdlToken;

public interface MetalineParser<T extends MetalineNode> {

	public boolean isMatch(List<KsdlToken> tokens);
	public T parse(Queue<KsdlToken> tokens);
}
