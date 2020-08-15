Hello World!
============

<WRITE>

.. code-block:: java
	
	KeroSecurityManager manager = KeroSecurityManager.getInstance();

	manager
	    .type(TestObject.class)
	        .defaultDeny()
	        .property("text")
	            .grantFor("OWNER");

	TestObject obj = new TestObject();

	TestObject protectedWithOwner = manager.protect(obj, "OWNER");
	TestObject protectedWithSomeRole = manager.protect(obj, "SOME_ROLE");

	protectedWithOwner.getText(); // <- OK

	protectedWithSomeRole.getText(); // <- throw AccessException