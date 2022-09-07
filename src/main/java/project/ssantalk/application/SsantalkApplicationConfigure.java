package project.ssantalk.application;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import tools.cluster.ClusteredResourceManagerHazelCast;
import tools.component.ScheduleManager;
import tools.http.RestTemplateProxy;
import tools.orm.jpa.JpaAopSpec.LoggingAspect;
import tools.spring.CompositeApplicationContainer;
import tools.spring.LogLevelManager;

/**
 * @author dragon
 * @since 2021. 03. 15.
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
@EnableConfigurationProperties(SsantalkApplicationProperties.class)
public class SsantalkApplicationConfigure {
	final CompositeApplicationContainer container;

	final LogLevelManager logLevelManager;

	final SsantalkApplicationProperties properties;

	@Bean
	public RestTemplateProxy getRestTemplateProxy(){
		return new RestTemplateProxy(properties.getRest());
	}

	@Bean
	public LoggingAspect getLoggingAspect() {
		return new LoggingAspect(	container,
									logLevelManager);
	}

	@Bean
	public ScheduleManager getScheduleManager(){
	    return new ScheduleManager();
	}
	
	@Bean
	public ClusteredResourceManagerHazelCast getClusteredResourceManagerHazelCast() {
		return new ClusteredResourceManagerHazelCast(properties.getCluster());
	}
}
