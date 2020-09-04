package com.kero.security.lang.parsers;

import java.util.HashMap;
import java.util.Map;
import java.util.Queue;

import com.kero.security.core.role.Role;
import com.kero.security.lang.nodes.PropagationLineNode;
import com.kero.security.lang.tokens.KeyWordToken;
import com.kero.security.lang.tokens.KsdlToken;
import com.kero.security.lang.tokens.NameToken;
import com.kero.security.managers.KeroAccessManager;

public class PropagationNodeParser extends KsdlNodeParserBase<PropagationLineNode>{

	@Override
	public PropagationLineNode parse(Queue<KsdlToken> tokens) {
		
		tokens.poll(); // META_LINE
		tokens.poll(); // PROPAGATION
		tokens.poll(); // OPEN_BLOCK
		
		if(!(tokens.peek() instanceof NameToken)) {
			
			throw new RuntimeException("Can't parse!");
		}
		
		NameToken fromRoleName = (NameToken) tokens.poll();
		
		Map<String, String> propagationMap = new HashMap<>();
		
		while(tokens.isEmpty()) {

			if(tokens.peek() != KeyWordToken.FORWARD_DIRECTION) throw new RuntimeException("Can't parse!");
			
			tokens.poll(); // FORWARD_DIRECTION
			
			if(!(tokens.peek() instanceof NameToken)) throw new RuntimeException("Can't parse!");
			
			NameToken toRoleName = (NameToken) tokens.poll();
		
			propagationMap.put(fromRoleName.getRaw(), toRoleName.getRaw());
			
			fromRoleName = toRoleName;
		}
		
		return new PropagationLineNode(propagationMap);
	}
}
