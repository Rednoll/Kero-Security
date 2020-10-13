package com.kero.security.lang.provider.resource;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import org.junit.jupiter.api.Test;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;

public class FileResourceTest {

	@Test
	public void getRawText() throws IOException {
		
		FileSystem fileSystem = Jimfs.newFileSystem(Configuration.unix());
		
		Path root = fileSystem.getPath("/root");
		Files.createDirectories(root);
		
		Path subFolder = fileSystem.getPath("/root/sub");
		Files.createDirectories(subFolder);
		
		Path file1 = fileSystem.getPath("/root/file1.k-s");
		Path file2 = fileSystem.getPath("/root/sub/file2.k-s");
		Path file3 = fileSystem.getPath("/root/sub/file3.txt");
		
		Files.write(file1, "test1".getBytes(), StandardOpenOption.CREATE_NEW);
		Files.write(file2, "test2".getBytes(), StandardOpenOption.CREATE_NEW);
		Files.write(file3, "test3".getBytes(), StandardOpenOption.CREATE_NEW);

		FileResource resource = new FileResource(root);
		
		assertEquals(resource.getRawText(), "test1\ntest2");
		
		resource = new FileResource(root, ".txt");
		
		assertEquals(resource.getRawText(), "test3");
	}
}
