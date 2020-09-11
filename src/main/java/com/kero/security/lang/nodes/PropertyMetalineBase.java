package com.kero.security.lang.nodes;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.property.Property;
import com.kero.security.lang.nodes.metaline.MetalineNodeBase;

public abstract class PropertyMetalineBase extends MetalineNodeBase {

	public abstract void interpret(KeroAccessAgent manager, Property property);
}
