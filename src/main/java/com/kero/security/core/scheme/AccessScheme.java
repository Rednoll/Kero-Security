package com.kero.security.core.scheme;

import java.util.Collections;
import java.util.Set;

import com.kero.security.core.DefaultAccessOwner;
import com.kero.security.core.access.annotations.Access;
import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.property.Property;

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
	
	public void setAliase(String name);
	public String getAliase();
	
	public KeroAccessAgent getAgent();
	
	public Set<Property> collectProperties();
	
	public default AccessScheme getParent() {
		
		Class<?> superClass = this.getTypeClass().getSuperclass();
	
		return getAgent().getOrCreateScheme(superClass);
	}
	
	public default Property getParentProperty(String name) {
		
		AccessScheme parent = this.getParent();
	
		if(parent.hasLocalProperty(name)) {
			
			return parent.getLocalProperty(name);
		}
		else {
			
			return parent.getParentProperty(name);
		}
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
			
			return Collections.emptySet();
		}

		@Override
		public Class<?> getTypeClass() {
			
			return null;
		}
		
		@Override
		public void setAliase(String aliase) {}

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
		
		@Override
		public Property getParentProperty(String name) {
			
			return Property.EMPTY;
		}
		
		@Override
		public AccessScheme getParent() {
			
			return this;
		}

		@Override
		public Set<Property> collectProperties() {
			
			return Collections.emptySet();
		}
	}
}
