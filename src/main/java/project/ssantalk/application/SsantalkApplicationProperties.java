package project.ssantalk.application;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import project.ssantalk.security.component.AuthenticationProperties;
import tools.cluster.ClusteredResourceSpec.HazelcastClusterProperties;
import tools.http.RestTemplateProperties;

/**
 * @author dragon
 * @since 2021. 05. 01.
 */
@Data
@ConfigurationProperties(prefix = "application", ignoreUnknownFields = false)
public class SsantalkApplicationProperties {
	HazelcastClusterProperties cluster;

	AuthenticationProperties authorization;

	RestTemplateProperties rest;

	Aria aria;

	@Data
	public static class Aria {
		private String key;
	}

}
