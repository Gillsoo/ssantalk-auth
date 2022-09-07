package project.ssantalk.application.service.component;

import org.springframework.stereotype.Component;
import project.ssantalk.security.UserMasterAuthentication;
import tools.cluster.ClusteredResourceSpec.ClusterMapAccessor;

/**
 * @author dragon
 * @since 2021. 05. 01.
 */
@Component
public class UserMasterAuthenticationCache
											extends
												ClusterMapAccessor<UserMasterAuthentication> {

}
