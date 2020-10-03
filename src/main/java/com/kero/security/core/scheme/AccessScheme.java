package com.kero.security.core.scheme;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import com.kero.security.core.DefaultAccessOwner;
import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.property.Access;
import com.kero.security.core.property.Property;
import com.kero.security.core.rules.def.DefaultAccessRule;

public interface AccessScheme extends DefaultAccessOwner {

	public static AccessScheme EMPTY = new Empty();
	
	public default Property getOrCreateLocalProperty(String name) {
		
		if(hasLocalProperty(name)) {
			
			return getLocalProperty(name);
		}
		else {
			
			return createLocalProperty(name);
		}
	}
	
	public void setInherit(boolean i);
	public boolean isInherit();
	
	public Property createLocalProperty(String name);
	public boolean hasLocalProperty(String name);
	public Property getLocalProperty(String name);
	public Set<Property> getLocalProperties();
	
	public Class<?> getTypeClass();
	
	public String getAliase();
	
	public KeroAccessAgent getAgent();
	
	public default AccessScheme getParent() {
		
		Class<?> superClass = this.getTypeClass().getSuperclass();
	
		return getAgent().getOrCreateScheme(superClass);
	}
	
	public Access determineDefaultAccess();
	
	public static class Empty implements AccessScheme {

		private Empty() {}
		
		@Override
		public void setDefaultAccess(Access access) {}

		@Override
		public boolean hasDefaultAccess() {
			
			return false;
		}

		@Override
		public Access getDefaultAccess() {
			
			return Access.UNKNOWN;
		}

		@Override
		public void setInherit(boolean i) {}

		@Override
		public boolean isInherit() {
		
			return false;
		}

		@Override
		public Property createLocalProperty(String name) {
			
			return Property.EMPTY;
		}

		@Override
		public boolean hasLocalProperty(String name) {
			
			return false;
		}

		@Override
		public Property getLocalProperty(String name) {
			
			return Property.EMPTY;
		}

		@Override
		public Set<Property> getLocalProperties() {
			
			return Collections.EMPTY_SET;
		}

		@Override
		public Class<?> getTypeClass() {
			
			return null;
		}

		@Override
		public String getAliase() {
			
			return null;
		}

		@Override
		public KeroAccessAgent getAgent() {
			
			return null;
		}

		@Override
		public Access determineDefaultAccess() {
			
			return Access.UNKNOWN;
		}
	}
}
