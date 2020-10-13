package com.kero.security.lang.provider.resource;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import org.junit.jupiter.api.Test;

public class FileResourceTest {

	@Test
	public void getRawText() throws IOException {
	
		Path dir = Files.createTempDirectory("k-s");
		
		Path file1 = Files.createTempFile(dir, "file1", ".k-s");
		Path file2 = Files.createTempFile(dir, "file2", ".k-s");
		
		try {
			
			Files.delete(file1);
		}
		catch(NoSuchFileException e) {
			
		}
		
		try {

			Files.delete(file2);
		}
		catch(NoSuchFileException e) {
			
		}
		
		Files.write(file1, "test1".getBytes(), StandardOpenOption.CREATE_NEW);
		Files.write(file2, "test2".getBytes(), StandardOpenOption.CREATE_NEW);

		FileResource resource = new FileResource(dir.toFile());
		
		assertEquals(resource.getRawText(), "test1\ntest2");
	}
}
