package com.kero.security.lang.parsers.metaline;

import java.util.HashMap;
import java.util.Map;

import com.kero.security.lang.collections.TokenSequence;
import com.kero.security.lang.nodes.metaline.PropagationMetaline;
import com.kero.security.lang.tokens.KeyWordToken;
import com.kero.security.lang.tokens.NameToken;

public class PropagationParser extends MetalineParserBase<PropagationMetaline> {
	
	public PropagationParser() {
		super("propagation");
		
	}

	@Override
	public boolean isMatch(TokenSequence tokens) {
		
		boolean superMatch = super.isMatch(tokens);
	
		if(!superMatch) return false;
		if(!tokens.isToken(2, KeyWordToken.OPEN_BLOCK)) return false;
		
		return true;
	}
	
	@Override
	public PropagationMetaline parse(TokenSequence tokens) {
		
		tokens.poll(); // META_LINE
		tokens.poll(); // PROPAGATION
		tokens.poll(); // OPEN_BLOCK
		
		if(!(tokens.peek() instanceof NameToken)) {
			
			throw new RuntimeException("Can't parse!");
		}
		
		NameToken fromRoleName = (NameToken) tokens.poll();
		
		Map<String, String> propagationMap = new HashMap<>();
		
		while(!tokens.isEmpty()) {
			
			if(tokens.peek() == KeyWordToken.CLOSE_BLOCK) {
			
				tokens.poll();
				break;
			}
			
			if(tokens.peek() != KeyWordToken.FORWARD_DIRECTION) throw new RuntimeException("Can't parse!");
			
			tokens.poll(); // FORWARD_DIRECTION
			
			if(!(tokens.peek() instanceof NameToken)) throw new RuntimeException("Can't parse!");
			
			NameToken toRoleName = (NameToken) tokens.poll();
		
			propagationMap.put(fromRoleName.getRaw(), toRoleName.getRaw());
			
			fromRoleName = toRoleName;
		}
		
		return new PropagationMetaline(propagationMap);
	}
}
