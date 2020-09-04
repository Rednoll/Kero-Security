package com.kero.security.lang.parsers;

import java.util.Queue;

import com.kero.security.lang.nodes.KsdlNode;
import com.kero.security.lang.tokens.KsdlToken;

public interface KsdlNodeParser<T extends KsdlNode> {

	public T parse(Queue<KsdlToken> tokens);
}
