package com.kero.security.lang.parsers;

import java.util.List;

import com.kero.security.lang.nodes.KsdlNode;
import com.kero.security.lang.tokens.KsdlToken;

public interface KsdlRootNodeParser<T extends KsdlNode> extends KsdlNodeParser<T> {

	public boolean isMatch(List<KsdlToken> tokens);
}
