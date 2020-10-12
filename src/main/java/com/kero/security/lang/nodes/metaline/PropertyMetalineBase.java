package com.kero.security.lang.nodes.metaline;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.property.Property;

public abstract class PropertyMetalineBase extends MetalineNodeBase {

	public abstract void interpret(KeroAccessAgent manager, Property property);
}
