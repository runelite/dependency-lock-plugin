/*
 * Copyright 2018 <Adam@sigterm.info>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.runelite.maven.lock;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;
import java.util.Objects;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;

@Mojo(
	name = "verify",
	defaultPhase = LifecyclePhase.VERIFY,
	requiresDependencyCollection = ResolutionScope.COMPILE_PLUS_RUNTIME,
	requiresDependencyResolution = ResolutionScope.COMPILE_PLUS_RUNTIME
)
public class VerifyMojo extends AbstractMojo
{
	private static final String HASH = "SHA-256";

	@Parameter(defaultValue = "${project}", required = true, readonly = true)
	private MavenProject project;

	@Parameter(defaultValue = "${session}", required = true, readonly = true)
	private MavenSession session;

	@Parameter(defaultValue = "false")
	private boolean skip;

	@Parameter(defaultValue = "true")
	private boolean ignoreUnknown;

	@Parameter
	private Lock[] locks;

	private final Log log = getLog();

	public void execute() throws MojoFailureException
	{
		final Set<Artifact> artifacts = project.getArtifacts();
		for (Artifact artifact : artifacts)
		{
			checkArtifact(artifact);
		}

		final Set<Artifact> pluginArtifacts = project.getPluginArtifacts();
		for (Artifact artifact : pluginArtifacts)
		{
			checkArtifact(artifact);
		}

		final Set<Artifact> extensionArtifacts = project.getExtensionArtifacts();
		for (Artifact artifact : extensionArtifacts)
		{
			checkArtifact(artifact);
		}
	}

	private void checkArtifact(Artifact artifact) throws MojoFailureException
	{
		if (artifact.getFile() == null)
		{
			// Have to do this to resolve paths for plugins...
			artifact = session.getLocalRepository().find(artifact);
		}

		for (Lock lock : locks)
		{
			if (lockMatches(lock, artifact))
			{
				checkHash(lock, artifact);
				return;
			}
		}

		if (ignoreUnknown || skip)
		{
			File file = artifact.getFile();

			if (file == null || !file.exists())
			{
				log.warn("No file for artifact " + artifact);
				return;
			}

			String hash;
			try
			{
				hash = hashFile(file, HASH);
			}
			catch (IOException | NoSuchAlgorithmException e)
			{
				throw new MojoFailureException("error hashing artifact", e);
			}

			log.warn("Unknown artifact " + artifact + " with hash " + HASH + ":" + hash);
			return;
		}

		throw new MojoFailureException("No lock for artifact " + artifact);
	}

	private static boolean lockMatches(Lock lock, Artifact artifact)
	{
		if (!Objects.equals(lock.getGroupId(), artifact.getGroupId()))
		{
			return false;
		}
		if (!Objects.equals(lock.getArtifactId(), artifact.getArtifactId()))
		{
			return false;
		}
		if (lock.getType() != null && !Objects.equals(lock.getType(), artifact.getType()))
		{
			return false;
		}
		if (lock.getClassifier() != null && !Objects.equals(lock.getClassifier(), artifact.getClassifier()))
		{
			return false;
		}

		return true;
	}

	private void checkHash(Lock lock, Artifact artifact) throws MojoFailureException
	{
		File file = artifact.getFile();
		if (!file.exists())
		{
			throw new MojoFailureException("Artifact file " + file + " does not exist");
		}

		String hash = extractHashType(lock.getHash());
		if (hash == null || hash.isEmpty())
		{
			throw new MojoFailureException("Invalid hash type for artifact " + artifact);
		}

		String digestString;

		try
		{
			digestString = hashFile(file, hash);
		}
		catch (NoSuchAlgorithmException | IOException e)
		{
			throw new MojoFailureException("error checking artifact", e);
		}

		if (!Objects.equals(hash + ":" + digestString, lock.getHash()))
		{
			if (skip)
			{
				log.warn("Mismatch in hash for artifact " + artifact + ": " + hash + ":" + digestString);
				return;
			}
			else
			{
				throw new MojoFailureException("Hash mismatch for artifact " + artifact + ": " + hash + digestString);
			}
		}

		log.debug("Hash match for " + artifact);
	}

	private static String extractHashType(String hash)
	{
		int idx = hash.indexOf(':');
		if (idx == -1)
		{
			return null;
		}

		return hash.substring(0, idx);
	}

	private static String hashFile(File file, String hash) throws IOException, NoSuchAlgorithmException
	{
		MessageDigest md = MessageDigest.getInstance(hash);
		try (FileInputStream in = new FileInputStream(file);
			 DigestInputStream dis = new DigestInputStream(in, md))
		{
			byte[] buf = new byte[1024 * 1024];
			while (dis.read(buf) != -1)
			{
			}
		}
		byte[] digest = md.digest();
		return byteToHex(digest);
	}

	private static String byteToHex(byte[] digest)
	{
		try (Formatter formatter = new Formatter())
		{
			for (byte b : digest)
			{
				formatter.format("%02x", b);
			}
			return formatter.toString();
		}
	}
}
