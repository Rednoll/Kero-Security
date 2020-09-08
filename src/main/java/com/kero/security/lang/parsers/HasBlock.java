package com.kero.security.lang.parsers;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import com.kero.security.lang.collections.TokenSequence;
import com.kero.security.lang.tokens.KeyWordToken;

public interface HasBlock<U> {

	public default List<U> parseBlock(TokenSequence tokens) {
		
		if(tokens.peek() != KeyWordToken.OPEN_BLOCK) return Collections.EMPTY_LIST;
		
		tokens.poll(); // OPEN_BLOCK
		
		List<U> units = new LinkedList<>();
		
		while(tokens.peek() != KeyWordToken.CLOSE_BLOCK) {
			
			units.add(parseBlockUnit(tokens));
		}
		
		tokens.poll(); // CLOSE_BLOCK
		
		return units;
	}
	
	public U parseBlockUnit(TokenSequence tokens);
}
