package project.ssantalk;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.autoconfigure.web.servlet.error.ErrorMvcAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Import;
import project.ssantalk.application.SsantalkApplicationProperties;
import tools.orm.jpa.JpaServiceConfigure;
import tools.spring.CompositeApplicationConfigure;

@SpringBootApplication(exclude = {
        ErrorMvcAutoConfiguration.class,
        UserDetailsServiceAutoConfiguration.class
})
@EnableConfigurationProperties({
        SsantalkApplicationProperties.class
})
@Import({
        CompositeApplicationConfigure.class,
        JpaServiceConfigure.class
})
public class SsantalkAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(SsantalkAuthApplication.class, args);
    }

}
