package com.kero.security.lang.nodes;

import com.kero.security.core.KeroAccessManager;
import com.kero.security.core.property.Property;
import com.kero.security.lang.nodes.metaline.MetalineNodeBase;

public abstract class PropertyMetalineBase extends MetalineNodeBase {

	public abstract void interpret(KeroAccessManager manager, Property property);
}
